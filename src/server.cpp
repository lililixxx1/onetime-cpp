// server.cpp — 服务端实现：一次性密钥链接 + 本机金库的 HTTP 服务。
//
// 安全设计不可破坏（改动前必读）：
//   1. 纯内存存储：密文只在进程内存 map，重启即清空（金库是显式落盘功能）
//   2. AES-256-GCM：解密密钥只存在于链接里，服务端内存无明文密钥
//   3. 严格一次性：读取-删除在同一把锁内原子完成
//   4. 日志零泄密：只记事件与字节数（金库条目名允许），绝不记路径/链接/ID/key/令牌/内容
//   5. 作废令牌零留存：服务端只存 SHA-256，恒时比较；令牌错误与不存在同回 404
//   6. hostGuard 防 DNS rebinding
//   7. csrfGuard 防跨站写入；/vault POST 强制 application/json
//   8. 防点击劫持：CSP frame-ancestors 'none' + X-Frame-Options: DENY
//   9. 内存封顶：1000 条 / 64 MiB，超限 429
//  10. 金库一键一文件：同目录临时文件 + rename 原子重写，条目间零接触
//  11. 默认只绑 127.0.0.1
//  12. 所有响应走 secureHeader()
#include "server.h"

#include "crypto.h"
#include "util.h"
#include "platform.h"

#include <algorithm>
#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <csignal>
#endif

#include "settings.h"

namespace fs = std::filesystem;

namespace onetime {
namespace {

constexpr size_t kMaxSecretSize = 1 << 20; // 单条密钥上限 1 MiB
constexpr size_t kMaxHeader = 32 * 1024;   // 请求头上限
constexpr int kIOTimeoutMs = 15000;
constexpr int kConnBudgetMs = 30000;

// ---------------- 日志：只记事件与字节数，绝不记密钥材料 ----------------

// 可选文件 sink：runServer 启动期按 cfg.logToFile 一次性开启（无运行时开关竞态）。
// 超过 1 MiB 时启动即轮转为 .old，之后只追加。
namespace {
std::mutex g_logMu;
std::ofstream g_logSink;
}

void openLogFile(const std::string& path) {
    std::error_code ec;
    fs::create_directories(fs::u8path(path).parent_path(), ec); // 首次运行 ~/.onetime 尚不存在
    if (fs::exists(fs::u8path(path), ec)) {
        auto sz = fs::file_size(fs::u8path(path), ec);
        if (!ec && sz > (1024ull * 1024)) {
            plat::moveReplace(path, path + ".old", true);
        }
    }
    std::lock_guard<std::mutex> lk(g_logMu);
    g_logSink.open(fs::u8path(path), std::ios::binary | std::ios::app);
}

void logEvent(const char* fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    {
        std::lock_guard<std::mutex> lk(g_logMu);
        if (g_logSink.is_open()) {
            std::tm tm;
            plat::localTime(time(nullptr), tm);
            g_logSink << std::setw(2) << std::setfill('0') << tm.tm_mon + 1 << '-'
                      << std::setw(2) << tm.tm_mday << ' ' << std::setw(2) << tm.tm_hour << ':'
                      << std::setw(2) << tm.tm_min << ':' << std::setw(2) << tm.tm_sec << ' '
                      << buf << "\n";
            g_logSink.flush();
        }
    }
    plat::debugLogLine("onetime: ");
    plat::debugLogLine(buf);
    plat::debugLogLine("\n");
    // 有控制台（AttachConsole / 终端启动场景）时同时打到 stderr
    if (plat::stderrIsConsole()) {
        fprintf(stderr, "%s\n", buf);
        fflush(stderr);
    }
}

std::string lower(std::string_view s) {
    std::string out(s);
    for (char& c : out)
        if (c >= 'A' && c <= 'Z') c += 32;
    return out;
}

// 取 host:port 的 host 部分（无端口则原样，去 [] 括号），小写。
std::string hostOnly(std::string_view hostport) {
    std::string_view h = hostport;
    if (!h.empty() && h.front() == '[') { // [::1]:8787
        auto close = h.find(']');
        if (close != std::string_view::npos) h = h.substr(1, close - 1);
    } else {
        auto colon = h.rfind(':');
        // 排除裸 IPv6 "::1"（无端口场景）
        if (colon != std::string_view::npos && h.substr(0, colon).find(':') == std::string_view::npos)
            h = h.substr(0, colon);
    }
    return lower(h);
}

bool isIpLiteral(std::string_view h) {
    if (h.empty()) return false;
    std::string s(h);
    if (s.front() == '[' && s.back() == ']') s = s.substr(1, s.size() - 2);
    unsigned char buf[16];
    return inet_pton(AF_INET, s.c_str(), buf) == 1 ||
           inet_pton(AF_INET6, s.c_str(), buf) == 1;
}

std::string joinHostPort(std::string_view h, std::string_view port) {
    if (h.find(':') != std::string_view::npos) // IPv6
        return "[" + std::string(h) + "]:" + std::string(port);
    return std::string(h) + ":" + std::string(port);
}

// ---------------- HTTP 请求/响应 ----------------

struct Request {
    std::string method, path, query, version;
    std::map<std::string, std::string> headers; // 键已小写
    std::string body;
    bool bodyTruncated = false; // 实体长于读取上限

    bool has(const char* k, std::string* v = nullptr) const {
        auto it = headers.find(k);
        if (it == headers.end()) return false;
        if (v) *v = it->second;
        return true;
    }
};

struct Response {
    int status = 200;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    void set(const char* k, const std::string& v) { headers.emplace_back(k, v); }
};

// 所有响应统一补齐安全头（结构性保证，不依赖各 handler 自觉）
void secureHeader(Response& r) {
    r.set("X-Content-Type-Options", "nosniff");
    r.set("Cache-Control", "no-store");
    r.set("Content-Security-Policy",
          "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
          "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
    r.set("X-Frame-Options", "DENY");
    r.set("Referrer-Policy", "no-referrer");
}

void errText(Response& r, int status, const char* msg) {
    r.status = status;
    r.set("Content-Type", "text/plain; charset=utf-8");
    r.body = std::string(msg) + "\n";
}

// /s/ 路径统一失败：404 且空体。空体是刻意的：
// 接收方常用 curl -o 落盘，错误文案会污染目标文件；"文件为空"即等价于取用失败。
void gone(Response& r) { r.status = 404; }

// csrfGuard：拦截浏览器跨站写入。curl/agent 不带这些头，不受影响。
bool csrfGuard(const Request& req, Response& r) {
    std::string sfs;
    if (req.has("sec-fetch-site", &sfs) && sfs != "same-origin" && sfs != "none") {
        errText(r, 403, "forbidden: cross-site request");
        return false;
    }
    std::string origin, host;
    req.has("origin", &origin);
    req.has("host", &host);
    if (!origin.empty() && origin != "http://" + host) {
        errText(r, 403, "forbidden: cross-site origin");
        return false;
    }
    return true;
}

// ---------------- 内存存储（每实例独立，测试可并行多套配置） ----------------

struct Entry {
    std::string ct;    // 密文 || tag
    std::string nonce; // 12 字节
    Clock::time_point exp;
    uint8_t tok[32];   // 作废令牌的 SHA-256（令牌本体只在创建响应头出现一次）
};

struct Store {
    std::mutex mu;
    std::unordered_map<std::string, Entry> m;
    size_t total = 0; // 当前密文总字节
    // 惰性清理过期记录（须持锁调用）
    void sweep() {
        auto now = Clock::now();
        for (auto it = m.begin(); it != m.end();) {
            if (now > it->second.exp) {
                total -= it->second.ct.size();
                it = m.erase(it);
            } else {
                ++it;
            }
        }
    }
};

struct Server {
    ServerConfig cfg;
    Store store;
    std::mutex vaultMu; // 保护金库文件并发写入
    std::string listenHost;
    fs::path vaultDir;
};

// ---------------- 金库：一钥一文件 ----------------

// 原子写入单个条目文件：同目录临时文件 + rename，任意时刻磁盘上只有完整版本。
bool writeVaultEntry(const fs::path& dir, const std::string& name, const std::string& value) {
    std::error_code ec;
    fs::create_directories(dir, ec);
    if (!fs::is_directory(dir)) return false;

    uint8_t rnd[3];
    if (!secureRandom(rnd, sizeof rnd)) return false;
    char suffix[8];
    snprintf(suffix, sizeof suffix, "%02x%02x%02x", rnd[0], rnd[1], rnd[2]);
    std::string tmpName = ".entry-" + std::string(suffix);

    {
        FILE* f = plat::fopenWrite((dir / tmpName).u8string());
        if (!f) return false;
        std::string data = value + "\n";
        size_t n = fwrite(data.data(), 1, data.size(), f);
        fclose(f);
        if (n != data.size()) {
            plat::removeFile((dir / tmpName).u8string());
            return false;
        }
    }
    if (!plat::moveReplace((dir / tmpName).u8string(), (dir / fs::u8path(name)).u8string(), true)) {
        plat::removeFile((dir / tmpName).u8string());
        return false;
    }
    return true;
}

// 删除单个条目文件；不存在视为成功（与旧版语义一致）。
bool deleteVaultEntry(const fs::path& dir, const std::string& name) {
    return plat::removeFile((dir / fs::u8path(name)).u8string());
}

// 列出条目名（排序）。只认符合名字规则的普通文件，临时文件与子目录天然排除。
bool listVaultNames(const fs::path& dir, std::vector<std::string>& names) {
    std::error_code ec;
    if (!fs::exists(dir, ec)) return true;
    for (auto it = fs::directory_iterator(dir, ec); !ec && it != fs::directory_iterator();
         it.increment(ec)) {
        std::error_code lec;
        if (!it->is_regular_file(lec)) continue;
        std::string n = it->path().filename().u8string();
        if (validName(n)) names.push_back(n);
    }
    if (ec) return false;
    std::sort(names.begin(), names.end());
    return true;
}

// 旧版单文件金库 <dir>.env 首次升级导入一键一文件布局。
// 仅在目录尚不存在时执行一次；完成后旧文件改名 .imported 原样保留。
void migrateLegacyVault(const fs::path& dir) {
    std::error_code ec;
    if (fs::exists(dir, ec)) return; // 新布局目录已存在，不碰旧文件

    fs::path legacy = dir; // <dir>.env
    legacy += ".env";
    FILE* f = plat::fopenRead(legacy.u8string());
    if (!f) return; // 无旧文件
    std::string data;
    {
        char buf[4096];
        size_t n;
        while ((n = fread(buf, 1, sizeof buf, f)) > 0) data.append(buf, n);
        fclose(f);
    }
    if (trimSpace(data).empty()) return; // 空旧文件：不迁移也不改名

    if (!data.empty() && data.back() == '\n') data.pop_back(); // TrimSuffix 一个尾换行
    int n = 0;
    size_t start = 0;
    while (start <= data.size()) {
        size_t end = data.find('\n', start);
        if (end == std::string::npos) end = data.size();
        std::string_view line(data.data() + start, end - start);
        auto eq = line.find('=');
        if (eq != std::string_view::npos && eq > 0 && validName(line.substr(0, eq))) {
            std::string name(line.substr(0, eq));
            std::string value(trimSpace(line.substr(eq + 1)));
            if (!writeVaultEntry(dir, name, value)) {
                logEvent("vault legacy import stopped after %d entries (write failed)", n);
                return;
            }
            ++n;
        }
        if (end == data.size()) break;
        start = end + 1;
    }
    fs::path imported = dir;
    imported += ".env.imported";
    if (plat::moveReplace(legacy.u8string(), imported.u8string(), false))
        logEvent("vault legacy import: %d entries (old file kept as .imported)", n);
    else
        logEvent("vault legacy import: %d entries (old file kept in place)", n);
}

// ---------------- 扁平 JSON：{"name": "...", "secret": "..."} ----------------
// 手写最小解析器（服务器不引第三方库）。语法非法、name/secret 非字符串 → 失败；
// 未知键任意合法 JSON 值均忽略。

struct JsonCursor {
    const char* p;
    const char* end;
};

void skipWs(JsonCursor& c) {
    while (c.p < c.end && (*c.p == ' ' || *c.p == '\t' || *c.p == '\r' || *c.p == '\n')) ++c.p;
}

bool parseString(JsonCursor& c, std::string& out);

bool skipValue(JsonCursor& c, int depth) {
    if (depth > 32 || c.p >= c.end) return false;
    char ch = *c.p;
    if (ch == '"') {
        std::string ignored;
        return parseString(c, ignored);
    }
    if (ch == '{' || ch == '[') {
        char close = (ch == '{') ? '}' : ']';
        ++c.p;
        skipWs(c);
        if (c.p < c.end && *c.p == close) {
            ++c.p;
            return true;
        }
        while (c.p < c.end) {
            if (!skipValue(c, depth + 1)) return false;
            skipWs(c);
            if (c.p < c.end && *c.p == ',') {
                ++c.p;
                skipWs(c);
                continue;
            }
            if (c.p < c.end && *c.p == close) {
                ++c.p;
                return true;
            }
            return false;
        }
        return false;
    }
    if (ch == 't' && c.end - c.p >= 4 && strncmp(c.p, "true", 4) == 0) { c.p += 4; return true; }
    if (ch == 'f' && c.end - c.p >= 5 && strncmp(c.p, "false", 5) == 0) { c.p += 5; return true; }
    if (ch == 'n' && c.end - c.p >= 4 && strncmp(c.p, "null", 4) == 0) { c.p += 4; return true; }
    if (ch == '-' || ch == '+' || (ch >= '0' && ch <= '9')) {
        while (c.p < c.end && ((*c.p >= '0' && *c.p <= '9') || *c.p == '-' || *c.p == '+' ||
                               *c.p == '.' || *c.p == 'e' || *c.p == 'E'))
            ++c.p;
        return true;
    }
    return false;
}

void utf8Encode(unsigned cp, std::string& out) {
    if (cp < 0x80) {
        out.push_back((char)cp);
    } else if (cp < 0x800) {
        out.push_back((char)(0xc0 | (cp >> 6)));
        out.push_back((char)(0x80 | (cp & 0x3f)));
    } else if (cp < 0x10000) {
        out.push_back((char)(0xe0 | (cp >> 12)));
        out.push_back((char)(0x80 | ((cp >> 6) & 0x3f)));
        out.push_back((char)(0x80 | (cp & 0x3f)));
    } else {
        out.push_back((char)(0xf0 | (cp >> 18)));
        out.push_back((char)(0x80 | ((cp >> 12) & 0x3f)));
        out.push_back((char)(0x80 | ((cp >> 6) & 0x3f)));
        out.push_back((char)(0x80 | (cp & 0x3f)));
    }
}

bool parseHex4(JsonCursor& c, unsigned& out) {
    if (c.end - c.p < 4) return false;
    out = 0;
    for (int i = 0; i < 4; ++i) {
        char h = c.p[i];
        out <<= 4;
        if (h >= '0' && h <= '9') out |= (unsigned)(h - '0');
        else if (h >= 'a' && h <= 'f') out |= (unsigned)(h - 'a' + 10);
        else if (h >= 'A' && h <= 'F') out |= (unsigned)(h - 'A' + 10);
        else return false;
    }
    c.p += 4;
    return true;
}

bool parseString(JsonCursor& c, std::string& out) {
    if (c.p >= c.end || *c.p != '"') return false;
    ++c.p;
    out.clear();
    while (c.p < c.end) {
        unsigned char ch = (unsigned char)*c.p;
        if (ch == '"') {
            ++c.p;
            return true;
        }
        if (ch == '\\') {
            ++c.p;
            if (c.p >= c.end) return false;
            char e = *c.p++;
            switch (e) {
                case '"': out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case '/': out.push_back('/'); break;
                case 'b': out.push_back('\b'); break;
                case 'f': out.push_back('\f'); break;
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                case 'u': {
                    unsigned cp;
                    if (!parseHex4(c, cp)) return false;
                    if (cp >= 0xd800 && cp <= 0xdbff && c.end - c.p >= 6 &&
                        c.p[0] == '\\' && c.p[1] == 'u') {
                        c.p += 2;
                        unsigned lo;
                        if (!parseHex4(c, lo) || lo < 0xdc00 || lo > 0xdfff) return false;
                        cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                    }
                    utf8Encode(cp, out);
                    break;
                }
                default: return false;
            }
            continue;
        }
        if (ch < 0x20) return false; // 控制字符必须转义
        out.push_back((char)ch);
        ++c.p;
    }
    return false;
}

bool parseVaultJson(const std::string& body, std::string& name, std::string& secret) {
    JsonCursor c{body.data(), body.data() + body.size()};
    skipWs(c);
    if (c.p >= c.end || *c.p != '{') return false;
    ++c.p;
    skipWs(c);
    if (c.p < c.end && *c.p == '}') return true; // 字段缺失 → 后续按空值校验失败
    while (c.p < c.end) {
        std::string key;
        if (!parseString(c, key)) return false;
        skipWs(c);
        if (c.p >= c.end || *c.p != ':') return false;
        ++c.p;
        skipWs(c);
        if (key == "name" || key == "secret") {
            if (c.p >= c.end || *c.p != '"') return false; // 目标字段必须为字符串
            if (!parseString(c, key == "name" ? name : secret)) return false;
        } else {
            if (!skipValue(c, 0)) return false;
        }
        skipWs(c);
        if (c.p < c.end && *c.p == ',') {
            ++c.p;
            skipWs(c);
            continue;
        }
        if (c.p < c.end && *c.p == '}') {
            ++c.p;
            skipWs(c);
            return c.p == c.end; // 尾随内容非法
        }
        return false;
    }
    return false;
}

std::string jsonQuote(const std::string& s) {
    // 金库名字仅 [A-Za-z0-9_]，无需转义；保守起见仍做最小校验
    std::string out = "\"";
    for (char c : s) {
        if ((unsigned char)c < 0x20 || c == '"' || c == '\\') return "\"\"";
        out.push_back(c);
    }
    out.push_back('"');
    return out;
}

// ---------------- 业务处理器 ----------------

void handleCreate(Server& sv, const Request& req, Response& r) {
    if (req.method != "POST") {
        errText(r, 405, "method not allowed");
        return;
    }
    if (!csrfGuard(req, r)) return;
    if (req.bodyTruncated || req.body.size() > kMaxSecretSize) {
        // 客户端余量已在读入阶段排空（至多再 1 MiB）
        errText(r, 413, "secret too large (max 1 MiB)");
        return;
    }
    if (req.body.empty()) {
        errText(r, 400, "empty secret");
        return;
    }

    int64_t ttlNs = sv.cfg.defaultTtlNs;
    auto q = std::string_view(req.query);
    size_t pos = 0;
    while (pos <= q.size()) {
        size_t amp = q.find('&', pos);
        if (amp == std::string_view::npos) amp = q.size();
        std::string_view kv = q.substr(pos, amp - pos);
        if (kv.substr(0, 4) == "ttl=" && kv.size() > 4) {
            int64_t d = parseDur(kv.substr(4));
            const int64_t minTtl = 30ll * 1000000000, maxTtl = 168ll * 3600 * 1000000000;
            if (d < 0 || d < minTtl || d > maxTtl) {
                errText(r, 400, "invalid ttl (allowed: 30s ~ 168h, e.g. 5m/1h/1d)");
                return;
            }
            ttlNs = d;
        }
        if (amp == q.size()) break;
        pos = amp + 1;
    }

    uint8_t key[32], id[16], token[32], nonce[12];
    if (!secureRandom(key, 32) || !secureRandom(id, 16) ||
        !secureRandom(token, 32) || !secureRandom(nonce, 12)) {
        errText(r, 500, "rng failed");
        return;
    }
    Sha256Digest tokHash;
    sha256(token, 32, tokHash);

    std::string ct;
    if (!aesGcmEncrypt(key, nonce, (const uint8_t*)req.body.data(), req.body.size(), ct)) {
        errText(r, 500, "crypto failed");
        return;
    }

    std::string sid = b64UrlEncode(id, 16);
    {
        std::lock_guard<std::mutex> lk(sv.store.mu);
        sv.store.sweep();
        if (sv.store.m.size() >= (size_t)sv.cfg.maxEntries ||
            sv.store.total + ct.size() > (size_t)sv.cfg.maxTotalCt) {
            errText(r, 429, "server busy: too many secrets in flight");
            return;
        }
        Entry e;
        e.ct = std::move(ct);
        e.nonce.assign((const char*)nonce, 12);
        e.exp = Clock::now() + std::chrono::duration_cast<Clock::duration>(std::chrono::nanoseconds(ttlNs));
        memcpy(e.tok, tokHash.data(), 32);
        sv.store.m[sid] = std::move(e);
        sv.store.total += sv.store.m[sid].ct.size();
    }

    std::string base = sv.cfg.publicBase;
    if (base.empty()) {
        std::string host = "127.0.0.1";
        req.has("host", &host);
        base = "http://" + canonicalLinkHost(host);
    }
    logEvent("secret created (ttl=%s, %lld bytes)", formatDur(ttlNs).c_str(),
             (long long)req.body.size());

    r.set("Content-Type", "text/plain; charset=utf-8");
    r.set("X-Delete-Token", b64UrlEncode(token, 32));
    r.set("X-Expires-In", std::to_string(ttlNs / 1000000000));
    r.body = base + "/s/" + sid + "." + b64UrlEncode(key, 32) + "\n";
}

// 创建者作废未读记录：须持 X-Delete-Token。令牌错误与记录不存在一律 404。
void burn(Server& sv, const Request& req, Response& r) {
    if (!csrfGuard(req, r)) return;
    std::string part = req.path.substr(3); // 去 "/s/"
    std::string sid = part;
    auto dot = part.find('.');
    if (dot != std::string::npos && dot > 0) sid = part.substr(0, dot);
    if (sid.empty()) {
        gone(r);
        return;
    }
    std::string tok;
    if (!req.has("x-delete-token", &tok) || !b64UrlDecode(tok, tok) || tok.size() != 32) {
        gone(r);
        return;
    }
    Sha256Digest sum;
    sha256((const uint8_t*)tok.data(), tok.size(), sum);
    bool ok = false;
    {
        std::lock_guard<std::mutex> lk(sv.store.mu);
        auto it = sv.store.m.find(sid);
        if (it != sv.store.m.end() && constTimeEq(sum.data(), it->second.tok, 32)) {
            sv.store.total -= it->second.ct.size();
            sv.store.m.erase(it);
            ok = true;
        }
    }
    if (!ok) {
        gone(r);
        return;
    }
    logEvent("secret burned by creator");
    r.set("Content-Type", "text/plain; charset=utf-8");
    r.body = "burned\n";
}

void handleGet(Server& sv, const Request& req, Response& r) {
    if (req.method == "GET") {
        // 继续
    } else if (req.method == "DELETE") {
        burn(sv, req, r);
        return;
    } else {
        errText(r, 405, "method not allowed");
        return;
    }
    std::string part = req.path.substr(3);
    auto dot = part.find('.');
    if (dot == std::string::npos || dot == 0 || dot + 1 == part.size()) {
        gone(r);
        return;
    }
    std::string sid = part.substr(0, dot);
    std::string keyRaw;
    if (!b64UrlDecode(part.substr(dot + 1), keyRaw) || keyRaw.size() != 32) {
        gone(r); // 链接形态非法：不消耗任何记录
        return;
    }
    uint8_t key[32];
    memcpy(key, keyRaw.data(), 32);

    // 严格一次性：读取-删除在同一把锁内原子完成
    Entry e;
    bool ok = false;
    {
        std::lock_guard<std::mutex> lk(sv.store.mu);
        auto it = sv.store.m.find(sid);
        if (it != sv.store.m.end()) {
            e = std::move(it->second);
            sv.store.total -= e.ct.size();
            sv.store.m.erase(it);
            ok = true;
        }
    }
    if (!ok) {
        gone(r);
        return;
    }
    if (Clock::now() > e.exp) {
        gone(r); // 已过期：记录随上面的删除一起销毁
        return;
    }
    std::string pt;
    if (e.nonce.size() != 12 ||
        !aesGcmDecrypt(key, (const uint8_t*)e.nonce.data(),
                       (const uint8_t*)e.ct.data(), e.ct.size(), pt)) {
        gone(r); // 链接被篡改（key 不匹配）：记录已作废
        return;
    }
    logEvent("secret retrieved (once-only, record destroyed)");
    r.set("Content-Type", "text/plain; charset=utf-8");
    r.body = std::move(pt);
}

void handleVault(Server& sv, const Request& req, Response& r) {
    if (req.method != "GET" && !csrfGuard(req, r)) return;

    if (req.method == "POST") {
        // 强制 JSON 声明：no-cors 跨站 fetch 发不出该头，与 Origin 校验双保险
        std::string ct;
        req.has("content-type", &ct);
        if (ct.rfind("application/json", 0) != 0) {
            errText(r, 415, "content-type must be application/json");
            return;
        }
        std::string name, secret;
        if (!parseVaultJson(req.body, name, secret)) {
            errText(r, 400, "invalid json");
            return;
        }
        name = std::string(trimSpace(name));
        secret = std::string(trimSpace(secret));
        if (!validName(name)) {
            errText(r, 400, "invalid name: letters/digits/underscore, must start with a letter, max 64");
            return;
        }
        if (secret.empty()) {
            errText(r, 400, "empty secret");
            return;
        }
        if (secret.size() > 4096 || hasNewline(secret)) {
            errText(r, 400, "secret must be single-line, max 4096 bytes");
            return;
        }
        bool overwritten = false;
        bool ok;
        {
            std::lock_guard<std::mutex> lk(sv.vaultMu);
            std::error_code ec;
            overwritten = fs::exists(sv.vaultDir / fs::u8path(name), ec) && !ec;
            ok = writeVaultEntry(sv.vaultDir, name, secret);
        }
        if (!ok) {
            errText(r, 500, "vault write failed");
            return;
        }
        logEvent("vaulted %s (%lld bytes)%s", name.c_str(), (long long)secret.size(),
                 overwritten ? " [overwritten]" : "");
        r.set("X-Vault-Path", sv.cfg.vaultDir);
        if (overwritten) r.set("X-Overwritten", "true"); // 同名覆盖：API 消费方可感知
        r.set("Content-Type", "application/json; charset=utf-8");
        r.body = "{\"ok\":true,\"name\":" + jsonQuote(name) + "}";
        return;
    }

    if (req.method == "DELETE") {
        std::string name;
        auto q = std::string_view(req.query);
        size_t pos = 0;
        while (pos <= q.size()) {
            size_t amp = q.find('&', pos);
            if (amp == std::string_view::npos) amp = q.size();
            std::string_view kv = q.substr(pos, amp - pos);
            if (kv.substr(0, 5) == "name=" && kv.size() > 5)
                name = std::string(kv.substr(5));
            if (amp == q.size()) break;
            pos = amp + 1;
        }
        name = std::string(trimSpace(name));
        if (!validName(name)) {
            errText(r, 400, "invalid name: letters/digits/underscore, must start with a letter, max 64");
            return;
        }
        bool ok;
        {
            std::lock_guard<std::mutex> lk(sv.vaultMu);
            ok = deleteVaultEntry(sv.vaultDir, name);
        }
        if (!ok) {
            errText(r, 500, "vault write failed");
            return;
        }
        logEvent("vault deleted %s", name.c_str());
        r.set("X-Vault-Path", sv.cfg.vaultDir);
        r.set("Content-Type", "application/json; charset=utf-8");
        r.body = "{\"ok\":true,\"deleted\":" + jsonQuote(name) + "}";
        return;
    }

    if (req.method == "GET") {
        // 仅返回名字清单，不含值
        std::vector<std::string> names;
        if (!listVaultNames(sv.vaultDir, names)) {
            errText(r, 500, "vault read failed");
            return;
        }
        std::string joined;
        for (size_t i = 0; i < names.size(); ++i) {
            if (i) joined += "\n";
            joined += names[i];
        }
        r.set("X-Vault-Path", sv.cfg.vaultDir);
        r.set("Content-Type", "text/plain; charset=utf-8");
        r.body = joined;
        return;
    }

    errText(r, 405, "method not allowed");
}

Response route(Server& sv, const Request& req) {
    Response r;
    secureHeader(r);
    std::string host;
    req.has("host", &host);
    if (!hostAllowed(host, sv.listenHost)) {
        errText(r, 403, "forbidden host");
        return r;
    }
    if (req.path == "/create") handleCreate(sv, req, r);
    else if (req.path.rfind("/s/", 0) == 0) handleGet(sv, req, r);
    else if (req.path == "/vault") handleVault(sv, req, r);
    else if (req.path == "/") {
        r.set("Content-Type", "text/plain; charset=utf-8");
        r.body =
            "onetime (C++/EUI-NEO) — 本机一次性密钥递送服务；界面为本机窗口程序\n"
            "API: POST /create[?ttl=30s~168h] | GET /s/<id>.<key>（一次） | "
            "DELETE /s/<id>.<key>（X-Delete-Token） | GET|POST|DELETE /vault\n";
    } else {
        errText(r, 404, "not found");
    }
    return r;
}

// ---------------- 连接层：读请求 / 写响应 ----------------

const char* reason(int code) {
    switch (code) {
        case 200: return "OK";
        case 400: return "Bad Request";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 413: return "Payload Too Large";
        case 415: return "Unsupported Media Type";
        case 429: return "Too Many Requests";
        case 431: return "Request Header Fields Too Large";
        case 500: return "Internal Server Error";
        default: return "Status";
    }
}

enum class RecvHead { Ok, Fail, TooLarge };

// 读到 \r\n\r\n 为止；超长置 TooLarge（调用方回 431）。
RecvHead recvHeader(plat::SockHandle s, std::string& head, uint64_t deadline) {
    char buf[8192];
    while (head.find("\r\n\r\n") == std::string::npos) {
        if (plat::nowMs() > deadline) return RecvHead::Fail;
        if (head.size() > kMaxHeader) return RecvHead::TooLarge;
        int n = recv(s, buf, (int)sizeof buf, 0);
        if (n <= 0) return RecvHead::Fail;
        head.append(buf, (size_t)n);
    }
    return head.size() > kMaxHeader ? RecvHead::TooLarge : RecvHead::Ok;
}

// 解析请求头（不含 body）。失败返回 false。
bool parseHead(const std::string& head, Request& req) {
    size_t lineEnd = head.find("\r\n");
    std::string reqLine = head.substr(0, lineEnd);
    auto sp1 = reqLine.find(' ');
    auto sp2 = reqLine.rfind(' ');
    if (sp1 == std::string::npos || sp2 == sp1) return false;
    req.method = reqLine.substr(0, sp1);
    std::string target = reqLine.substr(sp1 + 1, sp2 - sp1 - 1);
    req.version = reqLine.substr(sp2 + 1);
    auto q = target.find('?');
    if (q == std::string::npos) {
        req.path = target;
    } else {
        req.path = target.substr(0, q);
        req.query = target.substr(q + 1);
    }
    size_t pos = lineEnd + 2;
    while (pos < head.size()) {
        size_t eol = head.find("\r\n", pos);
        if (eol == pos) break; // 头结束
        if (eol == std::string::npos) break;
        std::string_view line(head.data() + pos, eol - pos);
        auto colon = line.find(':');
        if (colon != std::string_view::npos) {
            std::string key(line.substr(0, colon));
            for (char& c : key)
                if (c >= 'A' && c <= 'Z') c += 32;
            size_t vb = colon + 1;
            while (vb < line.size() && line[vb] == ' ') ++vb;
            size_t ve = line.size();
            while (ve > vb && (line[ve - 1] == ' ' || line[ve - 1] == '\r')) --ve;
            req.headers[key] = std::string(line.substr(vb, ve - vb));
        }
        pos = eol + 2;
    }
    return !req.method.empty() && !req.path.empty();
}

// 读 body：优先 Content-Length，其次 Transfer-Encoding: chunked。
// cap：最多读入的字节数；drain：超出 cap 后继续排空的上限（客户端友好：
// 排空至多再 1 MiB 后回 413，让客户端收得到响应；超出 cap+drain 即放弃读取）。
void recvBody(plat::SockHandle s, Request& req, size_t cap, size_t drain, uint64_t deadline,
              std::string& pending) {
    auto recvMore = [&](std::string& buf) -> bool {
        if (plat::nowMs() > deadline) return false;
        char tmp[16384];
        int n = recv(s, tmp, (int)sizeof tmp, 0);
        if (n <= 0) return false;
        buf.append(tmp, (size_t)n);
        return true;
    };
    size_t drainLeft = drain;
    auto feed = [&](const char* data, size_t len) -> bool {
        if (req.body.size() < cap) {
            size_t take = std::min(len, cap - req.body.size());
            req.body.append(data, take);
            data += take;
            len -= take;
        }
        if (len > 0) {
            req.bodyTruncated = true;
            if (len > drainLeft) return false;
            drainLeft -= len;
        }
        return true;
    };

    std::string te;
    bool chunked = req.has("transfer-encoding", &te) && te.find("chunked") != std::string::npos;
    std::string buf;
    buf.swap(pending);

    if (!chunked) {
        std::string cls;
        size_t want = 0;
        if (req.has("content-length", &cls)) {
            char* endp = nullptr;
            unsigned long long v = strtoull(cls.c_str(), &endp, 10);
            if (endp && *endp == '\0')
                want = (size_t)std::min<unsigned long long>(v, (unsigned long long)(cap + drain));
        }
        size_t got = 0;
        while (got < want) {
            if (buf.empty() && !recvMore(buf)) return;
            size_t take = std::min(buf.size(), want - got);
            if (!feed(buf.data(), take)) return;
            buf.erase(0, take);
            got += take;
        }
        return;
    }
    // chunked
    for (;;) {
        size_t eol;
        while ((eol = buf.find("\r\n")) == std::string::npos)
            if (!recvMore(buf)) return;
        size_t semi = buf.find(';');
        std::string sizeHex = buf.substr(0, semi < eol ? semi : eol);
        char* endp = nullptr;
        unsigned long long sz = strtoull(sizeHex.c_str(), &endp, 16);
        if (!endp || *endp != '\0' || sz > (unsigned long long)(cap + drain + 2)) return;
        buf.erase(0, eol + 2);
        if (sz == 0) return; // 忽略 trailer
        size_t got = 0;
        while (got < sz + 2) { // 数据 + 尾随 CRLF
            if (buf.empty() && !recvMore(buf)) return;
            size_t take = std::min(buf.size(), static_cast<size_t>(sz + 2 - got));
            if (got < sz) {
                size_t dTake = std::min(take, static_cast<size_t>(sz - got));
                if (!feed(buf.data(), dTake)) return;
            }
            buf.erase(0, take);
            got += take;
        }
    }
}

void sendAll(plat::SockHandle s, const char* data, size_t len) {
    size_t off = 0;
    while (off < len) {
        int n = plat::sendSock(s, data + off, (int)std::min(len - off, (size_t)65536));
        if (n <= 0) return;
        off += (size_t)n;
    }
}

// 连接并发上限：超限直接回最小 503 再关闭（慢客户端不能耗尽线程）。
constexpr int kMaxConns = 128;
const char* kBusyResponse =
    "HTTP/1.1 503 Service Unavailable\r\n"
    "Content-Type: text/plain; charset=utf-8\r\n"
    "Content-Length: 5\r\n"
    "X-Content-Type-Options: nosniff\r\n"
    "Cache-Control: no-store\r\n"
    "Connection: close\r\n\r\n"
    "busy\n";

void sendResponse(plat::SockHandle s, const Response& r) {
    std::string head = "HTTP/1.1 " + std::to_string(r.status) + " " + reason(r.status) + "\r\n";
    for (auto& kv : r.headers) head += kv.first + ": " + kv.second + "\r\n";
    head += "Content-Length: " + std::to_string(r.body.size()) + "\r\n";
    head += "Connection: close\r\n\r\n";
    sendAll(s, head.data(), head.size());
    if (!r.body.empty()) sendAll(s, r.body.data(), r.body.size());
}

void handleConnection(Server& sv, plat::SockHandle s) {
    plat::sockSetTimeoutMs(s, kIOTimeoutMs);
    int one = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&one, sizeof one);

    uint64_t deadline = plat::nowMs() + kConnBudgetMs;
    std::string head;
    auto hr = recvHeader(s, head, deadline);
    if (hr == RecvHead::TooLarge) {
        Response r;
        secureHeader(r);
        errText(r, 431, "request header too large");
        sendResponse(s, r);
        plat::sockClose(s);
        return;
    }
    if (hr != RecvHead::Ok) {
        plat::sockClose(s);
        return;
    }
    size_t headEnd = head.find("\r\n\r\n") + 4;
    std::string pending = head.substr(headEnd);

    Request req;
    if (!parseHead(head, req)) {
        Response r;
        secureHeader(r);
        errText(r, 400, "malformed request");
        sendResponse(s, r);
        plat::sockClose(s);
        return;
    }

    size_t cap = 0, drain = 0;
    if (req.method == "POST" && req.path == "/create") {
        cap = kMaxSecretSize + 1;
        drain = kMaxSecretSize;
    } else if (req.method == "POST" && req.path == "/vault") {
        cap = kMaxSecretSize;
    }
    if (cap > 0) {
        std::string expect;
        if (req.has("expect", &expect) && expect.find("100-continue") != std::string::npos)
            sendAll(s, "HTTP/1.1 100 Continue\r\n\r\n", 25);
        recvBody(s, req, cap, drain, deadline, pending);
    }

    sendResponse(s, route(sv, req));
    plat::sockClose(s);
}

} // namespace

std::string canonicalLinkHost(std::string_view hostport) {
    std::string_view h = hostport;
    std::string_view port;
    if (!h.empty() && h.front() == '[') {
        auto close = h.find(']');
        if (close != std::string_view::npos) {
            std::string_view rest = h.substr(close + 1); // ":8787" 或空
            if (!rest.empty() && rest.front() == ':') port = rest.substr(1);
            h = h.substr(1, close - 1);
        }
    } else {
        auto colon = h.rfind(':');
        if (colon != std::string_view::npos && h.substr(0, colon).find(':') == std::string_view::npos) {
            port = h.substr(colon + 1);
            h = h.substr(0, colon);
        }
    }
    std::string host = lower(h);
    if (host == "127.0.0.1" || host == "::1") host = "localhost";
    if (!port.empty()) return joinHostPort(host, port);
    return host;
}

bool hostAllowed(std::string_view hostHeader, std::string_view listenHost) {
    std::string h = hostOnly(hostHeader);
    return h == "localhost" || isIpLiteral(h) || h == lower(listenHost);
}

std::string defaultVaultDir() {
    return plat::homeDirUtf8() + "/.onetime/secrets";
}

bool runServer(const ServerConfig& cfgIn, std::string* chosenAddrOut) {
    // 每次调用独立实例（测试同进程可跑多套配置）。accept 循环永不返回，
    // 实例随线程栈常驻，进程退出即销毁——密文随之清空。
    Server sv;
    sv.cfg = cfgIn;
    if (sv.cfg.vaultDir.empty()) sv.cfg.vaultDir = defaultVaultDir();
    sv.vaultDir = fs::u8path(sv.cfg.vaultDir);

    if (sv.cfg.logToFile) openLogFile(serviceLogPath()); // 启动期常量：失败仅静默降级到调试通道

#ifndef _WIN32
    // POSIX：对端关闭后写 socket 默认 SIGPIPE 终止进程（服务端每连接主动
    // close，浏览器预取断开是常态）；sendSock 已带 MSG_NOSIGNAL，此处进程级兜底。
    signal(SIGPIPE, SIG_IGN);
#endif

    // -vault 指向已存在文件时快速失败：新语义是目录
    std::error_code fec;
    if (fs::exists(sv.vaultDir, fec) && !fs::is_directory(sv.vaultDir, fec)) {
        logEvent("vault path is a file; expecting a directory — pass the vault directory "
                 "(legacy <dir>.env is auto-imported on first start)");
        return false;
    }
    migrateLegacyVault(sv.vaultDir);
    sv.listenHost = hostOnly(sv.cfg.listenAddr);

    // 拆 host:port
    std::string_view addr = sv.cfg.listenAddr;
    std::string hostPart, portPart;
    if (!addr.empty() && addr.front() == '[') {
        auto close = addr.find(']');
        if (close == std::string_view::npos) {
            logEvent("invalid listen address");
            return false;
        }
        hostPart = std::string(addr.substr(1, close - 1));
        auto colon = addr.find(':', close);
        if (colon == std::string_view::npos) {
            logEvent("invalid listen address (missing port)");
            return false;
        }
        portPart = std::string(addr.substr(colon + 1));
    } else {
        auto colon = addr.rfind(':');
        if (colon == std::string_view::npos ||
            addr.substr(0, colon).find(':') != std::string::npos) {
            logEvent("invalid listen address (expect host:port)");
            return false;
        }
        hostPart = std::string(addr.substr(0, colon));
        portPart = std::string(addr.substr(colon + 1));
    }

    plat::AddrInfoList ais;
    if (!ais.resolve(hostPart, portPart, true)) {
        logEvent("cannot resolve listen address");
        return false;
    }

    plat::SockHandle listener = plat::kInvalidSock;
    for (size_t i = 0;; ++i) {
        plat::AddrInfoList::Entry ai;
        if (!ais.at(i, ai)) break;
        listener = socket(ai.family, ai.socktype, ai.protocol);
        if (listener == plat::kInvalidSock) continue;
#ifndef _WIN32
        // TIME_WAIT 快速重启（服务端每连接主动 close，
        // Linux 60s TIME_WAIT 窗口内重启会 bind 失败）
        int reuse = 1;
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof reuse);
#endif
        if (bind(listener, ai.addr, ai.addrlen) == 0 && listen(listener, kMaxConns) == 0)
            break;
        plat::sockClose(listener);
        listener = plat::kInvalidSock;
    }
    if (listener == plat::kInvalidSock) {
        logEvent("cannot listen on %s (port busy?)", sv.cfg.listenAddr.c_str());
        return false;
    }

    if (portPart == "0") {
        sockaddr_storage sa = {};
        socklen_t sl = sizeof sa;
        if (getsockname(listener, (sockaddr*)&sa, &sl) == 0) {
            char hostBuf[64] = {0}, servBuf[16] = {0};
            if (getnameinfo((sockaddr*)&sa, sl, hostBuf, sizeof hostBuf, servBuf, sizeof servBuf,
                            NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
                std::string h = lower(hostBuf);
                if (h == "127.0.0.1" || h == "::1") h = "localhost";
                sv.cfg.listenAddr = joinHostPort(h, servBuf);
            }
        }
    }
    if (chosenAddrOut) *chosenAddrOut = sv.cfg.listenAddr;

    logEvent("onetime listening on http://%s — secrets live in memory only, one-time retrieval",
             sv.cfg.listenAddr.c_str());

    // 每连接一线程：一个慢客户端不再阻塞其他连接。sv 在本函数栈上且
    // 循环永不返回，跨线程引用安全；计数在包装层统一递减
    //（handleConnection 早退分支多，散置会泄漏）。
    std::atomic<int> active{0};
    for (;;) {
        sockaddr_storage peer = {};
        socklen_t peerLen = sizeof peer;
        plat::SockHandle client = accept(listener, (sockaddr*)&peer, &peerLen);
        if (client == plat::kInvalidSock) continue;
        if (active.load(std::memory_order_relaxed) >= kMaxConns) {
            sendAll(client, kBusyResponse, strlen(kBusyResponse));
            plat::sockClose(client);
            continue;
        }
        active.fetch_add(1, std::memory_order_relaxed);
        std::thread([&sv, &active, client] {
            handleConnection(sv, client);
            active.fetch_sub(1, std::memory_order_release);
        }).detach();
    }
}

} // namespace onetime
