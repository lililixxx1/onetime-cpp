// tests/test_main.cpp — 安全不变量测试
//
// 覆盖：严格一次性、作废令牌（恒时比较、404 无预言）、TTL 边界、尺寸上限、
// 内存封顶（条数/字节）、hostGuard、csrfGuard、金库一键一文件与迁移、
// 并发抢单（只有第一个 GET 拿到 200）。
// 通过条件：全部 CHECK 通过；任一失败退出码非 0。
#include "../src/crypto.h"
#include "../src/httplite.h"
#include "../src/platform.h"
#include "../src/server.h"
#include "../src/settings.h"
#include "../src/util.h"

#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;

static int g_pass = 0, g_fail = 0;
#define CHECK(cond)                                                        \
    do {                                                                   \
        if (cond) {                                                        \
            ++g_pass;                                                      \
        } else {                                                           \
            ++g_fail;                                                      \
            printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);         \
        }                                                                  \
    } while (0)

static std::string g_tmp; // 测试根目录（<TEMP>/onetime-cpp-test）

static std::string tempDir(const char* name) { return g_tmp + "/" + name; }

// 在固定端口上启动服务线程，探测到根路径 200 即返回。
static void startServer(onetime::ServerConfig cfg) {
    std::thread([cfg] { onetime::runServer(cfg, nullptr); }).detach();
    for (int i = 0; i < 100; ++i) {
        auto r = onetime::httpCall(cfg.listenAddr, "GET", "/", "");
        if (r.status == 200) return;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    printf("FATAL: server %s did not come up\n", cfg.listenAddr.c_str());
    ++g_fail;
}

static std::string trimNl(std::string s) {
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
    return s;
}

// 从链接里取 "/s/..." 路径
static std::string sPath(const std::string& link) {
    auto pos = link.find("/s/");
    return link.substr(pos);
}

int main() {
    g_tmp = (fs::temp_directory_path() / "onetime-cpp-test").u8string();
    std::error_code ec;
    fs::remove_all(g_tmp, ec);
    fs::create_directories(g_tmp, ec);

    // ---------- 纯函数：hostGuard / canonicalLinkHost / parseDur / 名字规则 ----------
    CHECK(onetime::hostAllowed("localhost:18801", "127.0.0.1"));
    CHECK(onetime::hostAllowed("LOCALHOST", "127.0.0.1"));
    CHECK(onetime::hostAllowed("127.0.0.1:18801", "127.0.0.1"));
    CHECK(onetime::hostAllowed("[::1]:18801", "127.0.0.1"));
    CHECK(onetime::hostAllowed("192.168.1.5", "127.0.0.1")); // IP 字面量放行
    CHECK(!onetime::hostAllowed("evil.com", "127.0.0.1"));
    CHECK(!onetime::hostAllowed("sub.localhost", "127.0.0.1"));
    CHECK(onetime::hostAllowed("", "")); // HTTP/1.0 无 Host：监听地址同为空时放行
    CHECK(onetime::canonicalLinkHost("127.0.0.1:18801") == "localhost:18801");
    CHECK(onetime::canonicalLinkHost("[::1]:18801") == "localhost:18801");
    CHECK(onetime::canonicalLinkHost("localhost:18801") == "localhost:18801");
    CHECK(onetime::canonicalLinkHost("127.0.0.1") == "localhost");
    CHECK(onetime::parseDur("30s") == 30ll * 1000000000);
    CHECK(onetime::parseDur("1h30m") == 5400ll * 1000000000);
    CHECK(onetime::parseDur("168h") == 168ll * 3600 * 1000000000);
    CHECK(onetime::parseDur("1") < 0);   // 缺单位
    CHECK(onetime::parseDur("x") < 0);   // 非法字符
    CHECK(onetime::parseDur("") < 0);
    CHECK(onetime::parseDur("1d") < 0);  // parseDur 不支持 d 单位
    CHECK(onetime::validName("A"));
    CHECK(onetime::validName("a_B9"));
    CHECK(!onetime::validName("1abc"));
    CHECK(!onetime::validName("a-b"));
    CHECK(!onetime::validName("a.b"));
    CHECK(!onetime::validName(std::string(65, 'a')));

    // ---------- 加密与编码隔离测试 ----------
    {
        // 加密向量锁定（两平台共用）：SHA-256 公知向量 + AES-GCM 跨实现一致性
        // 期望值由 Windows CNG 生成（TC14/TC16 的 CT 前缀与 NIST GCM 官方向量
        // 一致可交叉印证）；Linux 自带实现（crypto_posix.cpp）必须逐字节复现。
        auto hexLoad = [](const char* s, uint8_t* out, size_t n) {
            for (size_t i = 0; i < n; ++i) {
                unsigned v = 0;
                if (sscanf(s + i * 2, "%2x", &v) != 1) v = 0;
                out[i] = (uint8_t)v;
            }
        };
        auto hexStr = [](const std::string& s) {
            std::string out;
            char b[3];
            for (unsigned char c : s) {
                snprintf(b, sizeof b, "%02x", c);
                out += b;
            }
            return out;
        };
        // SHA-256（FIPS 180-4 公知向量）
        {
            onetime::Sha256Digest d;
            onetime::sha256(nullptr, 0, d);
            CHECK(hexStr(std::string((const char*)d.data(), d.size())) ==
                  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
            onetime::sha256((const uint8_t*)"abc", 3, d);
            CHECK(hexStr(std::string((const char*)d.data(), d.size())) ==
                  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        }
        // AES-256-GCM（McGrew-Viega TC14/TC16/TC13 的 key/IV + 自定义中文混合）
        {
            uint8_t vkey[32], vnonce[12];
            hexLoad("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", vkey, 32);
            hexLoad("cafebabefacedbaddecaf888", vnonce, 12);
            uint8_t pt14[16];
            hexLoad("d9313225f88406e5a55909c5aff5269a", pt14, 16);
            std::string d1;
            CHECK(onetime::aesGcmEncrypt(vkey, vnonce, pt14, 16, d1));
            CHECK(hexStr(d1) ==
                  "522dc1f099567d07f47f37a32a84427d7ea353da7e9241a1d90d693a4954186b");
            uint8_t pt16[60];
            hexLoad("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
                    pt16, 60);
            std::string d2;
            CHECK(onetime::aesGcmEncrypt(vkey, vnonce, pt16, 60, d2));
            CHECK(hexStr(d2) ==
                  "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
                  "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662eb9f796c"
                  "8d356fc31a8433884b696f4f");
            CHECK(hexStr(d2.substr(0, 16)) == hexStr(d1.substr(0, 16))); // 同流同前缀
            std::string d3;
            CHECK(onetime::aesGcmEncrypt(vkey, vnonce, nullptr, 0, d3)); // 空明文：纯 tag
            CHECK(d3.size() == 16);
            CHECK(hexStr(d3) == "fd2caa16a5832e76aa132c1453eeda7e");
            uint8_t k2[32], n2[12];
            for (int i = 0; i < 32; ++i) k2[i] = (uint8_t)(i * 7 + 1);
            for (int i = 0; i < 12; ++i) n2[i] = (uint8_t)(200 - i);
            const char* zh = "敏捷的棕色狐狸跳过懒狗 0123456789";
            std::string d4;
            CHECK(onetime::aesGcmEncrypt(k2, n2, (const uint8_t*)zh, strlen(zh), d4));
            CHECK(hexStr(d4) ==
                  "243a10f90001ac8db1ad66594d814be787e8e93039e8bf22f3a29ba289a491e4"
                  "029997685f4babfa80f3ce9d8cd4e962d9b0c0e4cc0235fb475d78da");
            // 向量密文必须能按同向量解回（加密向量的反向完整性）
            std::string back;
            CHECK(onetime::aesGcmDecrypt(vkey, vnonce, (const uint8_t*)d2.data(), d2.size(), back));
            CHECK(back.size() == 60 && memcmp(back.data(), pt16, 60) == 0);
        }

        uint8_t key[32], nonce[12];
        for (int i = 0; i < 32; ++i) key[i] = (uint8_t)i;
        for (int i = 0; i < 12; ++i) nonce[i] = (uint8_t)(i + 100);
        std::string ct, pt;
        bool enc = onetime::aesGcmEncrypt(key, nonce, (const uint8_t*)"hello-secret", 12, ct);
        CHECK(enc);
        CHECK(ct.size() == 12 + 16); // 密文 || tag
        bool dec = onetime::aesGcmDecrypt(key, nonce, (const uint8_t*)ct.data(), ct.size(), pt);
        CHECK(dec);
        CHECK(pt == "hello-secret");
        key[0] ^= 1; // 错 key：认证必须失败
        CHECK(!onetime::aesGcmDecrypt(key, nonce, (const uint8_t*)ct.data(), ct.size(), pt));

        // base64url 往返（22/43 字符两种长度）
        std::string id16 = onetime::b64UrlEncode(key, 16), back;
        CHECK(onetime::b64UrlDecode(id16, back) && back.size() == 16);
        std::string k32 = onetime::b64UrlEncode(key, 32);
        CHECK(onetime::b64UrlDecode(k32, back) && back.size() == 32 && back != std::string(32, '\0'));
        CHECK(!onetime::b64UrlDecode("A", back)); // 长度模 4 = 1 非法
    }

    // ---------- 服务 A：常规配置 ----------
    const std::string A = "127.0.0.1:18801";
    {
        onetime::ServerConfig cfg;
        cfg.listenAddr = A;
        cfg.vaultDir = tempDir("vaultA");
        startServer(cfg);
    }

    {
        auto r = onetime::httpCall(A, "GET", "/", "");
        CHECK(r.status == 200);
        CHECK(r.body.find("onetime") != std::string::npos);
        CHECK(onetime::httpCall(A, "GET", "/nope", "").status == 404);
        // 安全头
        CHECK(r.headers.count("x-content-type-options") && r.headers["x-content-type-options"] == "nosniff");
        CHECK(r.headers.count("x-frame-options") && r.headers["x-frame-options"] == "DENY");
        CHECK(r.headers.count("content-security-policy"));
        CHECK(r.headers.count("referrer-policy"));
    }

    // 一次性取用 + 二次 404 空体 + 作废
    std::string burnedLink;
    {
        auto r = onetime::httpCall(A, "POST", "/create?ttl=1h", "hello-secret");
        CHECK(r.status == 200);
        std::string link = trimNl(r.body);
        CHECK(link.rfind("http://localhost:18801/s/", 0) == 0); // 回环规范化为 localhost
        CHECK(r.headers.count("x-delete-token"));
        CHECK(r.headers.count("x-expires-in") && r.headers["x-expires-in"] == "3600");
        std::string token = r.headers["x-delete-token"];

        auto g1 = onetime::httpCall(A, "GET", sPath(link), "");
        CHECK(g1.status == 200 && g1.body == "hello-secret");
        auto g2 = onetime::httpCall(A, "GET", sPath(link), "");
        CHECK(g2.status == 404 && g2.body.empty()); // 空体 404
        // 已取用后再作废 → 404（无存在性预言）
        std::vector<std::pair<std::string, std::string>> tok{{"X-Delete-Token", token}};
        CHECK(onetime::httpCall(A, "DELETE", sPath(link), "", tok).status == 404);
    }
    {
        auto r = onetime::httpCall(A, "POST", "/create?ttl=5m", "to-burn");
        CHECK(r.status == 200);
        burnedLink = trimNl(r.body);
        std::string token = r.headers["x-delete-token"];
        std::vector<std::pair<std::string, std::string>> tok{{"X-Delete-Token", token}};
        auto d = onetime::httpCall(A, "DELETE", sPath(burnedLink), "", tok);
        CHECK(d.status == 200 && d.body == "burned\n");
        CHECK(onetime::httpCall(A, "GET", sPath(burnedLink), "").status == 404);
        CHECK(onetime::httpCall(A, "DELETE", sPath(burnedLink), "", tok).status == 404); // 二次作废
        std::vector<std::pair<std::string, std::string>> bad{{"X-Delete-Token", "AAAA"}};
        CHECK(onetime::httpCall(A, "DELETE", sPath(burnedLink), "", bad).status == 404);
    }

    // 链接形态非法 → 404 空体，不消耗记录
    {
        CHECK(onetime::httpCall(A, "GET", "/s/abc", "").status == 404);
        CHECK(onetime::httpCall(A, "GET", "/s/.key", "").status == 404);
        CHECK(onetime::httpCall(A, "GET", "/s/abc.", "").status == 404);
        CHECK(onetime::httpCall(A, "GET", "/s/abcdefghijABCDEFGH.QUJD", "").status == 404); // key≠32B
        CHECK(onetime::httpCall(A, "PUT", "/s/abc.def", "").status == 405);
    }

    // TTL 边界
    {
        CHECK(onetime::httpCall(A, "POST", "/create?ttl=29s", "x").status == 400);
        CHECK(onetime::httpCall(A, "POST", "/create?ttl=30s", "x").status == 200);
        CHECK(onetime::httpCall(A, "POST", "/create?ttl=169h", "x").status == 400);
        CHECK(onetime::httpCall(A, "POST", "/create?ttl=168h", "x").status == 200);
        CHECK(onetime::httpCall(A, "POST", "/create?ttl=abc", "x").status == 400);
        auto r = onetime::httpCall(A, "POST", "/create?ttl=1h30m", "x");
        CHECK(r.status == 200 && r.headers["x-expires-in"] == "5400");
        CHECK(onetime::httpCall(A, "GET", "/create", "").status == 405);
    }

    // 尺寸
    {
        CHECK(onetime::httpCall(A, "POST", "/create", "").status == 400); // 空密钥
        std::string big((1 << 20) + 10, 'A');
        CHECK(onetime::httpCall(A, "POST", "/create", big).status == 413);
        std::string exact(1 << 20, 'B');
        CHECK(onetime::httpCall(A, "POST", "/create", exact).status == 200);
    }

    // hostGuard（HTTP 层）
    {
        auto r = onetime::httpCall(A, "GET", "/", "",
                                   {{"Host", "evil.com"}});
        CHECK(r.status == 403);
        CHECK(onetime::httpCall(A, "GET", "/", "", {{"Host", "localhost:18801"}}).status == 200);
        CHECK(onetime::httpCall(A, "GET", "/", "", {{"Host", "10.1.2.3:18801"}}).status == 200);
    }

    // csrfGuard（HTTP 层）
    {
        CHECK(onetime::httpCall(A, "POST", "/create", "x",
                                {{"Origin", "http://evil.com"}}).status == 403);
        CHECK(onetime::httpCall(A, "POST", "/create", "x",
                                {{"Origin", "http://127.0.0.1:18801"}}).status == 200);
        CHECK(onetime::httpCall(A, "POST", "/create", "x",
                                {{"Sec-Fetch-Site", "cross-site"}}).status == 403);
        CHECK(onetime::httpCall(A, "POST", "/create", "x",
                                {{"Sec-Fetch-Site", "same-origin"}}).status == 200);
        // GET /s/ 不做 CSRF 校验（读取无副作用）
        CHECK(onetime::httpCall(A, "GET", "/s/zz.zz", "",
                                {{"Origin", "http://evil.com"}}).status == 404);
    }

    // 金库（vaultA）
    {
        std::vector<std::pair<std::string, std::string>> json{{"Content-Type", "application/json"}};
        CHECK(onetime::httpCall(A, "POST", "/vault", "{\"name\":\"X\",\"secret\":\"1\"}",
                                {{"Content-Type", "text/plain"}}).status == 415);
        CHECK(onetime::httpCall(A, "POST", "/vault", "not-json", json).status == 400);
        CHECK(onetime::httpCall(A, "POST", "/vault", "{\"name\":\"1abc\",\"secret\":\"v\"}", json).status == 400);
        CHECK(onetime::httpCall(A, "POST", "/vault", "{\"name\":\"a-b\",\"secret\":\"v\"}", json).status == 400);
        CHECK(onetime::httpCall(A, "POST", "/vault", "{\"name\":\"OK\",\"secret\":\"a\nb\"}", json).status == 400);
        CHECK(onetime::httpCall(A, "POST", "/vault", "{\"name\":\"OK\",\"secret\":\"\"}", json).status == 400);
        CHECK(onetime::httpCall(A, "POST", "/vault",
                                "{\"name\":\"OK\",\"secret\":\"" + std::string(4097, 'k') + "\"}",
                                json).status == 400);

        auto put = onetime::httpCall(A, "POST", "/vault", "{\"name\":\"Alpha\",\"secret\":\"sk-123\"}", json);
        CHECK(put.status == 200 && put.body == "{\"ok\":true,\"name\":\"Alpha\"}");
        CHECK(put.headers.count("x-overwritten") == 0); // 新建不带覆盖标记
        CHECK(fs::is_regular_file(tempDir("vaultA") + "/Alpha"));
        // 覆盖后文件内容整体替换，且响应带 X-Overwritten: true
        {
            auto ow = onetime::httpCall(A, "POST", "/vault", "{\"name\":\"Alpha\",\"secret\":\"v2\"}", json);
            CHECK(ow.status == 200);
            auto h = ow.headers.find("x-overwritten");
            CHECK(h != ow.headers.end() && h->second == "true");
        }
        {
            FILE* f = fopen((tempDir("vaultA") + "/Alpha").c_str(), "rb");
            CHECK(f != nullptr);
            if (f) {
                std::string got;
                char buf[64];
                size_t n;
                while ((n = fread(buf, 1, sizeof buf, f)) > 0) got.append(buf, n);
                fclose(f);
                CHECK(got == "v2\n");
            }
        }
        // 名字首尾空白被修剪
        auto put2 = onetime::httpCall(A, "POST", "/vault", "{\"name\":\" Gamma \",\"secret\":\"x\"}", json);
        CHECK(put2.status == 200 && put2.body.find("Gamma") != std::string::npos);

        // 清单只含名字；诱饵条目不被带出值
        {
            FILE* f = fopen((tempDir("vaultA") + "/Zeta").c_str(), "wb");
            if (f) { fputs("DECOY-VALUE\n", f); fclose(f); }
        }
        auto list = onetime::httpCall(A, "GET", "/vault", "");
        CHECK(list.status == 200);
        CHECK(list.body == "Alpha\nGamma\nZeta"); // 排序，不含值
        CHECK(list.headers.count("x-vault-path"));

        // 删除
        CHECK(onetime::httpCall(A, "DELETE", "/vault?name=Alpha", "").status == 200);
        CHECK(!fs::exists(tempDir("vaultA") + "/Alpha"));
        CHECK(onetime::httpCall(A, "DELETE", "/vault?name=Alpha", "").status == 200); // 不存在也成功
        CHECK(onetime::httpCall(A, "DELETE", "/vault?name=1x", "").status == 400);
    }

    // 并发抢单：8 线程抢同一链接，恰好一个 200
    {
        auto r = onetime::httpCall(A, "POST", "/create", "race-secret");
        std::string link = sPath(trimNl(r.body));
        std::atomic<int> ok200 = 0;
        std::atomic<int> miss404 = 0;
        std::vector<std::thread> ths;
        for (int i = 0; i < 8; ++i)
            ths.emplace_back([&] {
                auto g = onetime::httpCall(A, "GET", link, "");
                if (g.status == 200 && g.body == "race-secret") ok200.fetch_add(1);
                else if (g.status == 404 && g.body.empty()) miss404.fetch_add(1);
            });
        for (auto& t : ths) t.join();
        CHECK(ok200.load() == 1);
        CHECK(miss404.load() == 7);
    }

    // ---------- 服务 B：条数封顶 ----------
    {
        onetime::ServerConfig cfg;
        cfg.listenAddr = "127.0.0.1:18802";
        cfg.vaultDir = tempDir("vaultB");
        cfg.maxEntries = 3;
        cfg.maxTotalCt = 1 << 30;
        startServer(cfg);
        const std::string B = "127.0.0.1:18802";
        CHECK(onetime::httpCall(B, "POST", "/create", "1111111111").status == 200);
        CHECK(onetime::httpCall(B, "POST", "/create", "2222222222").status == 200);
        CHECK(onetime::httpCall(B, "POST", "/create", "3333333333").status == 200);
        CHECK(onetime::httpCall(B, "POST", "/create", "4444444444").status == 429);
        CHECK(onetime::httpCall(B, "POST", "/create", "5555555555").status == 429);
    }

    // ---------- 服务 C：密文字节封顶 ----------
    {
        onetime::ServerConfig cfg;
        cfg.listenAddr = "127.0.0.1:18803";
        cfg.vaultDir = tempDir("vaultC");
        cfg.maxEntries = 1000;
        cfg.maxTotalCt = 4096; // 密文 = 明文 + 16B tag
        startServer(cfg);
        const std::string C = "127.0.0.1:18803";
        std::string kb(1100, 'k'); // 每条密文 = 1100 + 16B tag = 1116
        CHECK(onetime::httpCall(C, "POST", "/create", kb).status == 200); // 1116
        CHECK(onetime::httpCall(C, "POST", "/create", kb).status == 200); // 2232
        CHECK(onetime::httpCall(C, "POST", "/create", kb).status == 200); // 3348
        CHECK(onetime::httpCall(C, "POST", "/create", kb).status == 429); // 3348+1116=4464 > 4096
    }

    // ---------- 服务 D：旧版 .env 迁移 ----------
    {
        // 先写 <dir>.env，不建目录；runServer 启动时自动迁移
        std::string legacy = tempDir("vaultD") + ".env";
        FILE* f = fopen(legacy.c_str(), "wb");
        if (f) {
            fputs("# comment\nA1=one\nA2=two\nBad-Name=skip\nA1=second\nC3 = spaced\n", f);
            fclose(f);
        }
        onetime::ServerConfig cfg;
        cfg.listenAddr = "127.0.0.1:18804";
        cfg.vaultDir = tempDir("vaultD");
        startServer(cfg);
        const std::string D = "127.0.0.1:18804";
        auto list = onetime::httpCall(D, "GET", "/vault", "");
        CHECK(list.status == 200 && list.body == "A1\nA2"); // 同名后行覆盖前行；坏行不迁
        CHECK(fs::exists(tempDir("vaultD") + "/A1"));
        {
            FILE* f2 = fopen((tempDir("vaultD") + "/A1").c_str(), "rb");
            CHECK(f2 != nullptr);
            if (f2) {
                std::string got;
                char buf[32];
                size_t n;
                while ((n = fread(buf, 1, sizeof buf, f2)) > 0) got.append(buf, n);
                fclose(f2);
                CHECK(got == "second\n");
            }
        }
        CHECK(fs::exists(legacy + ".imported"));
        CHECK(!fs::exists(legacy));
    }

    // ---------- 设置：解析/序列化纯函数、容错与 CLI 优先级 ----------
    {
        using onetime::Settings;
        // 默认往返
        Settings def;
        CHECK(onetime::parseSettings(onetime::serializeSettings(def).c_str()).defaultTtlIdx ==
              def.defaultTtlIdx);
        {
            Settings s = onetime::parseSettings(onetime::serializeSettings(def));
            CHECK(s.publicBase.empty() && !s.autoCopyLink && s.clearNameAfterPut && s.showRecords);
            CHECK(!s.darkTheme && s.uiScale == 1.25f && !s.autostart && !s.minimizeToTray &&
                  !s.logToFile);
        }
        // 改字段往返相等（值含 = 的 public_base）
        {
            Settings s;
            s.defaultTtlIdx = 3;
            s.publicBase = "https://x.example/?a=b=c";
            s.listenAddr = "0.0.0.0:9999";
            s.autoCopyLink = true;
            s.darkTheme = true;
            s.uiScale = 1.5f;
            std::string text = onetime::serializeSettings(s);
            Settings r = onetime::parseSettings(text);
            CHECK(r.defaultTtlIdx == 3 && r.publicBase == "https://x.example/?a=b=c");
            CHECK(r.listenAddr == "0.0.0.0:9999" && r.autoCopyLink && r.darkTheme &&
                  r.uiScale == 1.5f);
        }
        // 容错：BOM/CRLF/注释/未知键/缺行/非法值回退
        {
            std::string text = "\xEF\xBB\xBF# comment\r\nunknown_key=1\r\ndefault_ttl=7d\r\n"
                               "ui_scale=abc\r\nlisten_addr=not-a-port\r\npublic_base=https://x.y/\r\n";
            Settings s = onetime::parseSettings(text);
            CHECK(s.defaultTtlIdx == 4);                        // 7d
            CHECK(s.uiScale == 1.25f);                           // 非法回退默认
            CHECK(s.listenAddr.empty());                         // 非法地址拒绝
            CHECK(s.publicBase == "https://x.y");                // 尾斜杠剥离
        }
        // ttl 档位映射
        CHECK(onetime::ttlIdxFromLabel("30m") == 0 && onetime::ttlIdxFromLabel("7d") == 4 &&
              onetime::ttlIdxFromLabel("bogus") == -1);
        CHECK(std::string(onetime::ttlLabelFromIdx(2)) == "8h");
        // host:port 校验
        CHECK(onetime::validHostPort("127.0.0.1:8787") && onetime::validHostPort("localhost:80"));
        CHECK(!onetime::validHostPort("127.0.0.1") && !onetime::validHostPort(":80"));
        CHECK(!onetime::validHostPort("a:0") && !onetime::validHostPort("a:65536") &&
              !onetime::validHostPort("a:x"));
        // 优先级：settings 覆盖默认，显式命令行键最终胜出
        {
            Settings s;
            s.listenAddr = "127.0.0.1:9001";
            s.publicBase = "https://from-settings";
            s.vaultDir = "D:/from-settings";
            std::string addr = "127.0.0.1:8787", base = "https://from-cli", vault;
            onetime::applySettingsToConfig(addr, base, vault, s, onetime::kCliBase);
            CHECK(addr == "127.0.0.1:9001");     // addr 未显式 → settings 生效
            CHECK(base == "https://from-cli");   // base 显式 → CLI 胜出
            CHECK(vault == "D:/from-settings");  // vault 未显式 → settings 生效
            // 全部显式：settings 完全不介入
            std::string a2 = "10.0.0.1:1", b2, v2 = "E:/cli";
            onetime::applySettingsToConfig(a2, b2, v2, s,
                                           onetime::kCliAddr | onetime::kCliBase | onetime::kCliVault);
            CHECK(a2 == "10.0.0.1:1" && b2.empty() && v2 == "E:/cli");
            // settings 地址为空 → 保持默认
            Settings empty;
            std::string a3 = "127.0.0.1:8787", b3, v3;
            onetime::applySettingsToConfig(a3, b3, v3, empty, 0);
            CHECK(a3 == "127.0.0.1:8787");
        }
        // 文件 IO 往返（临时目录）
        {
            std::string path = tempDir("settings-roundtrip.txt");
            Settings s;
            s.defaultTtlIdx = 2;
            s.logToFile = true;
            CHECK(onetime::saveSettingsFile(path, s));
            Settings r;
            CHECK(onetime::loadSettingsFile(path, r));
            CHECK(r.defaultTtlIdx == 2 && r.logToFile);
            fs::remove(path, ec);
        }
        // 文件尾部读取边界：缺失 / 空文件 / 小于 cap 全量 / 超量截断
        {
            std::string path = tempDir("tail.log");
            CHECK(onetime::readFileTail(tempDir("no-such.log"), 64).empty());
            { FILE* f = fopen(path.c_str(), "wb"); if (f) fclose(f); }
            CHECK(onetime::readFileTail(path, 64).empty());
            { FILE* f = fopen(path.c_str(), "wb"); if (f) { fputs("hello-log", f); fclose(f); } }
            CHECK(onetime::readFileTail(path, 64) == "hello-log");
            CHECK(onetime::readFileTail(path, 4) == "-log"); // 只取尾部 4 字节
            fs::remove(path, ec);
        }
    }

    fs::remove_all(g_tmp, ec);
    printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
