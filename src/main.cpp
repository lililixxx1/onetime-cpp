// main.cpp — EUI-NEO 前端 + 内置 onetime 服务线程
//
// 形态：单进程 = 原生窗口（人用）+ 127.0.0.1 HTTP 服务（curl/agent 用）。
// 窗口与 curl 一样只是本服务的普通客户端：所有守卫、加密、一次性语义
// 只在服务端存在一份（src/server.cpp），界面不含任何安全判断的副本。
//
// 界面 v2（票据式设计语言，业务与架构不变）：
//   浅色纸感主题：#f4f5f5 底 + #fdfdfd 卡面 + 深青绿 #0e6e64 强调 + 砖红 #a8433c 危险色
//   票据化结果区：NO. 编号 + 有效期 + 打孔虚线 + 按钮三级语义（主操作/次操作/作废）
//   状态反馈补全：生成中/写入中/作废中 loading、复制 1.6s 反馈、金库两步确认删除
//   轻量会话记录：最近 8 条操作（只存窗口内存，关窗即清）
//   快捷键：金库表单内 (Ctrl+)Enter 直接存入；链接页 Ctrl+Enter 生成。注意 EUI-NEO
//   输入组件会消费聚焦时的 Enter（框架行为，应用层不可拦截），故链接页多行框内
//   Ctrl+Enter 表现为换行，快捷键仅在输入框外生效。
//
// 功能：
//   链接页：贴入密钥 → 生成一次性链接 → 复制链接 / 复制给 Agent 的说明 / 作废
//   金库页：条目名+值 存入（一键一文件）→ 名字清单 → 两步确认删除
//   Agent 说明模板内置默认文案；可在面板编辑并保存到
//   ~/.onetime/agent-template.{link,vault}.txt，恢复默认即删文件。
#include "httplite.h" // 先引 platform.h（winsock2 在 windows.h 之前的顺序在此头内自洽）

#include "eui_neo.h"

#include "server.h"
#include "settings.h"
#include "util.h"
#include "icon_png.h"

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "advapi32.lib")
#else
#include "core/window/window_backend.h" // 剪贴板（框架 GLFW/SDL 后端均实现）
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
extern char** environ;
#endif

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <functional>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace app {

using namespace onetime;

namespace fs = std::filesystem;

// ---------------- Agent 说明模板（内置默认文案） ----------------

static const char* kLinkTpl =
    "[onetime] 这是一次性密钥链接，取用一次后立即失效。请确保明文不进入对话记录：\n"
    "1. 用一条命令直接存入目标文件，不要打印内容：curl -s -o ~/.onetime/received.key -w "
    "\"%{http_code}\" \"{link}\"（PowerShell: Invoke-WebRequest \"{link}\" -OutFile "
    "$HOME/.onetime/received.key）；有约定位置则存约定位置\n"
    "2. 校验结果：状态码非 200、命令连接失败/超时、PowerShell 报错、或落盘文件为空——都说明"
    "链接已耗尽/过期或服务未启动，只回复“取用失败”，不要谎报已存；失败时留下的空文件删掉即可\n"
    "3. 成功后只回复“已取到，已存到 <路径>”。禁止 cat、读回、用任何文件读取工具查看、或在回复中"
    "复述明文\n"
    "4. 取用后链接即失效，转存要及时";

static const char* kVaultTpl =
    "本机金库新增了一条密钥，名字叫 {name}。需要使用时只读取这一个文件：~/.onetime/secrets/"
    "{name}（若服务启动时用 -vault 指定了目录，则是该目录下的同名文件），文件内容即密钥值。加载示例："
    "export {name}=\"$(cat ~/.onetime/secrets/{name})\"。禁止读取该目录下的其他文件——那些不属于你。"
    "不要把值拼进命令行参数（会进进程列表和 shell 历史），不要在回复里复述值，也不要把值写进日志；"
    "确认文件可读后只回复“已就绪：{name}”。";

static std::string substitute(std::string tpl, const std::string& from, const std::string& to) {
    size_t pos = 0;
    while ((pos = tpl.find(from, pos)) != std::string::npos) {
        tpl.replace(pos, from.size(), to);
        pos += to.size();
    }
    return tpl;
}

// ---------------- 主题 token ----------------

struct AppTheme {
    components::theme::ThemeColorTokens tokens;
    core::Color pageBg;     // #f4f5f5 页面底
    core::Color accentDeep; // #0a5750 hover 深青绿
    core::Color accentWash; // #e3efec 青绿洗底
    core::Color warn;       // #a8433c 砖红
    core::Color warnWash;   // #f6ebe9 砖红洗底
    core::Color dim;        // #4d5754 弱文字
    core::Color ink2;       // #55625f 次级文字
    core::Color hair;       // #d9dfdd 分隔线
    core::Color hairSoft;   // #e7ebea 细分隔线
    core::Color linkWell;   // #f0f4f3 链接展示底
};

static core::Color hexColor(float r, float g, float b) { return {r, g, b, 1.0f}; }

// #RRGGBB 直写（深色表用，免长浮点字面量）
static core::Color hexC(unsigned v) {
    return hexColor(((v >> 16) & 255) / 255.0f, ((v >> 8) & 255) / 255.0f, (v & 255) / 255.0f);
}

static Settings g_settings; // 启动加载的持久设置（UI 态在 st.settings；声明先于 appTheme 选择器）

static AppTheme buildLightTheme() {
    AppTheme a;
    a.tokens = components::theme::light();
    a.tokens.background = hexColor(0.957f, 0.961f, 0.961f); // #f4f5f5
    a.tokens.primary = hexColor(0.055f, 0.431f, 0.392f);    // #0e6e64
    a.tokens.surface = hexColor(0.992f, 0.992f, 0.992f);    // #fdfdfd
    a.tokens.surfaceHover = hexColor(0.906f, 0.922f, 0.918f);
    a.tokens.surfaceActive = hexColor(0.839f, 0.878f, 0.867f);
    a.tokens.text = hexColor(0.110f, 0.141f, 0.149f);       // #1c2426
    a.tokens.border = hexColor(0.851f, 0.875f, 0.867f);     // #d9dfdd
    a.tokens.dark = false;
    a.pageBg = a.tokens.background;
    a.accentDeep = hexColor(0.039f, 0.341f, 0.314f);        // #0a5750
    a.accentWash = hexColor(0.890f, 0.937f, 0.925f);        // #e3efec
    a.warn = hexColor(0.659f, 0.263f, 0.235f);              // #a8433c
    a.warnWash = hexColor(0.965f, 0.922f, 0.914f);          // #f6ebe9
    a.dim = hexColor(0.302f, 0.341f, 0.329f);              // #4d5754，偏深以保证 11px 小字对比度
    a.ink2 = hexColor(0.333f, 0.384f, 0.373f);              // #55625f
    a.hair = a.tokens.border;
    a.hairSoft = hexColor(0.906f, 0.922f, 0.918f);          // #e7ebea
    a.linkWell = hexColor(0.941f, 0.957f, 0.953f);          // #f0f4f3
    return a;
}

// 深色表：tokens.dark = true 必设（组件库十余处交互态混色按它分支）；
// 洗底/分隔线等辅助色全部配套换深，沿浅色表同款字段清单逐项覆写。
static AppTheme buildDarkTheme() {
    AppTheme a;
    a.tokens = components::theme::dark();
    a.tokens.background = hexC(0x16201e);
    a.tokens.primary = hexC(0x2f9e8f);   // 深底上提亮的主青绿
    a.tokens.surface = hexC(0x1d2927);
    a.tokens.surfaceHover = hexC(0x24312f);
    a.tokens.surfaceActive = hexC(0x2b3a37);
    a.tokens.text = hexC(0xd8e2df);
    a.tokens.border = hexC(0x2c3a37);
    a.tokens.dark = true;
    a.pageBg = a.tokens.background;
    a.accentDeep = hexC(0x35b3a2);       // 深色下 hover 取更亮而非更深
    a.accentWash = hexC(0x223330);
    a.warn = hexC(0xcf6f66);
    a.warnWash = hexC(0x3a2622);
    a.dim = hexC(0x9fb0ac);
    a.ink2 = hexC(0xb7c6c2);
    a.hair = a.tokens.border;
    a.hairSoft = hexC(0x24302d);
    a.linkWell = hexC(0x1a2523);
    return a;
}

static const AppTheme& appTheme() {
    static const AppTheme light = buildLightTheme();
    static const AppTheme dark = buildDarkTheme();
    return g_settings.darkTheme ? dark : light;
}

// ---------------- 命令行（-addr/-base/-ttl/-vault） ----------------

struct Cli {
    ServerConfig cfg;
    std::string addr = "127.0.0.1:8787";
    uint32_t explicitKeys = 0; // 命令行显式传入的键（settings.h 的 kCli* 位），settings 不得覆盖
};

static Cli g_cli;
static std::atomic<int> g_serverState{0};  // 0 启动中 / 2 监听失败（runServer 返回 false 即置 2）
static std::string g_vaultDisplay; // 金库目录（页脚展示）
static std::string g_headerStatus; // 页眉状态行（启动时拼好，compose 直接引用，免每次重组分配）
static const char* g_projectUrl = "https://github.com/lililixxx1/onetime-cpp"; // 页脚项目地址（可点击）

// 取 UTF-8 命令行参数（应用入口在框架手里，拿不到 argc/argv）。
// Windows：CommandLineToArgvW + 宽转窄；Linux：/proc/self/cmdline（NUL 分段，
// 首段即 argv[0]，与下方"跳过首段"的解析循环一致）。失败返回空——回退默认参数。
static std::vector<std::string> getArgvUtf8() {
    std::vector<std::string> args;
#ifdef _WIN32
    int argc = 0;
    LPWSTR* argvW = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argvW) return args;
    for (int i = 0; i < argc; ++i) {
        int need = WideCharToMultiByte(CP_UTF8, 0, argvW[i], -1, nullptr, 0, nullptr, nullptr);
        std::string s((size_t)(need > 0 ? need - 1 : 0), '\0');
        if (need > 1) WideCharToMultiByte(CP_UTF8, 0, argvW[i], -1, &s[0], need, nullptr, nullptr);
        args.push_back(s);
    }
    LocalFree(argvW);
#else
    FILE* f = fopen("/proc/self/cmdline", "rb");
    if (!f) return args;
    std::string raw;
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) raw.append(buf, n);
    fclose(f);
    size_t start = 0;
    while (start < raw.size()) {
        size_t end = raw.find('\0', start);
        if (end == std::string::npos) end = raw.size();
        args.push_back(raw.substr(start, end - start));
        start = end + 1;
    }
#endif
    return args;
}

static void parseCli() {
    std::vector<std::string> args = getArgvUtf8();
    for (size_t i = 1; i < args.size(); ++i) {
        std::string a = args[i];
        std::string key;
        if (a.rfind("--", 0) == 0) key = a.substr(2);      // --addr
        else if (a.rfind("-", 0) == 0) key = a.substr(1);  // -addr
        else continue;                                      // 非旗标
        if ((key == "addr" || key == "base" || key == "ttl" || key == "vault") &&
            i + 1 < args.size()) {
            std::string v = args[++i];
            if (key == "addr") {
                if (onetime::validHostPort(v)) {
                    g_cli.addr = v;
                    g_cli.explicitKeys |= kCliAddr;
                }
            } else if (key == "base") {
                g_cli.cfg.publicBase = onetime::stripTrailingSlash(v);
                g_cli.explicitKeys |= kCliBase;
            } else if (key == "ttl") {
                int64_t ns = parseDur(v);
                const int64_t lo = 30ll * 1000000000, hi = 168ll * 3600 * 1000000000;
                if (ns >= lo && ns <= hi) g_cli.cfg.defaultTtlNs = ns; // 非法值静默忽略，不占显式位
            } else if (key == "vault") {
                g_cli.cfg.vaultDir = v;
                g_cli.explicitKeys |= kCliVault;
            }
        }
    }
}

// ---------------- 剪贴板 ----------------
// Windows：CF_UNICODETEXT 原生路径（零依赖窗口句柄）；Linux：EUI-NEO 的 GLFW
// 剪贴板（调用点全部在 UI 点击回调，窗口必然存活，满足其前置条件）。
static bool copyText(const std::string& utf8) {
#ifdef _WIN32
    int need = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
    if (need <= 0) return false;
    HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, (SIZE_T)need * sizeof(wchar_t));
    if (!h) return false;
    wchar_t* w = (wchar_t*)GlobalLock(h);
    if (!w) {
        GlobalFree(h);
        return false;
    }
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, w, need);
    GlobalUnlock(h);
    bool ok = false;
    if (OpenClipboard(nullptr)) {
        EmptyClipboard();
        ok = SetClipboardData(CF_UNICODETEXT, h) != nullptr;
        CloseClipboard();
    }
    if (!ok) GlobalFree(h);
    return ok;
#else
    core::window::setClipboardText(utf8);
    return true;
#endif
}

// ---------------- 页面状态（单窗口业务对象，只在 UI 线程读写） ----------------

using SteadyClock = std::chrono::steady_clock;

struct SessionRecord {
    std::string time; // hh:mm
    std::string kind; // 链接 / 金库
    std::string no;   // 票号 / 条目名
    std::string tag;  // ttl / 已作废 / 落盘 / 已删除
};

struct PageState {
    int tab = 0; // 0 链接 1 金库 2 设置（设置经页眉按钮进入，lastTab 记住返回目标）
    int lastTab = 0;
    // 链接页
    std::string secretDraft, link, token, ticketNo, expireAt, linkError;
    int ttlIdx = 1;
    // Agent 说明模板（可编辑，持久化到 ~/.onetime/）
    std::string tplLink, tplVault;            // 生效模板（默认或用户已保存）
    std::string tplDraftLink, tplDraftVault;  // 面板编辑缓冲
    bool tplEditOpen = false;
    std::string tplNote;                      // 保存/恢复反馈
    SteadyClock::time_point tplNoteAt{};
    // 金库页
    std::string vName, vSecret, vNote, vaultOkName, vaultOkDir;
    bool vaultOverwritten = false; // 最近一次存入是否覆盖了同名旧值（X-Overwritten）
    bool vaultLoaded = false;
    std::vector<std::string> vaultNames;
    SteadyClock::time_point vaultRetryAt{}; // 初始清单拉取失败后的退避点（epoch=立即重试）
    // 两步确认删除（armed 状态 3 秒有效）
    std::string armedDelete;
    SteadyClock::time_point armedAt{};
    // 复制反馈（1.6 秒按钮文案切换）
    std::string copyDoneId;
    SteadyClock::time_point copyDoneAt{};
    // 会话记录（最近 8 条，只存窗口内存）
    std::vector<SessionRecord> records;
    // 设置页：持久值在 settings；以下为页面瞬态
    Settings settings;
    std::string setDraftBase, setDraftAddr, setDraftVault; // 文本设置编辑缓冲
    std::string setSavedBase, setSavedAddr, setSavedVault; // 对比初值（保存按钮仅在有改动时可用）
    std::string setNote; // 设置页校验失败反馈（warn 色；随 timer.tpl 一起回弹）
    bool logViewOpen = false;
    std::string logViewText;
    // 反馈
    bool toastVisible = false;
    std::string toastTitle, toastMsg;
};
static PageState st;

static const char* kTtls[] = {"30m", "1h", "8h", "24h", "168h"};
static const char* kTtlLabels[] = {"30m", "1h", "8h", "24h", "7d"};

static void showToast(const std::string& title, const std::string& msg) {
    st.toastTitle = title;
    st.toastMsg = msg;
    st.toastVisible = true;
}

// ---------------- 小工具：票号 / 时钟 / 记录 / 反馈 ----------------

static std::string hhmmNow() {
    time_t t = std::time(nullptr);
    std::tm tm{};
    plat::localTime(t, tm);
    char buf[8];
    snprintf(buf, sizeof buf, "%02d:%02d", tm.tm_hour, tm.tm_min);
    return buf;
}

static std::string expireAtFrom(int64_t seconds) {
    time_t t = std::time(nullptr) + (time_t)seconds;
    std::tm tm{};
    plat::localTime(t, tm);
    char buf[8];
    snprintf(buf, sizeof buf, "%02d:%02d", tm.tm_hour, tm.tm_min);
    return std::string("有效期至 ") + buf;
}

// 链接 /s/<id>.<key> → 票号 = id 前 8 位大写
static std::string ticketNoOf(const std::string& link) {
    auto pos = link.find("/s/");
    if (pos == std::string::npos) return "--------";
    auto start = pos + 3;
    auto end = link.find('.', start);
    if (end == std::string::npos) end = link.size();
    std::string id = link.substr(start, std::min<size_t>(8, end - start));
    for (char& c : id)
        if (c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
    return id;
}

static void pushRecord(const std::string& kind, const std::string& no, const std::string& tag) {
    SessionRecord r;
    r.time = hhmmNow();
    r.kind = kind;
    r.no = no;
    r.tag = tag;
    st.records.insert(st.records.begin(), std::move(r));
    if (st.records.size() > 8) st.records.resize(8);
}

static bool isArmed(const std::string& name) {
    if (st.armedDelete != name) return false;
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(SteadyClock::now() - st.armedAt);
    return ms.count() < 3000;
}

static std::string copyLabel(const std::string& id, const std::string& normal,
                             const std::string& done) {
    if (st.copyDoneId == id) {
        auto ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(SteadyClock::now() - st.copyDoneAt);
        if (ms.count() < 1600) return done;
    }
    return normal;
}

static void copyWithFeedback(const std::string& id, const std::string& text) {
    if (copyText(text)) {
        st.copyDoneId = id;
        st.copyDoneAt = SteadyClock::now();
    }
}

// ---------------- 设置：持久化 / 自启 / 日志查看 ----------------

static void persistSettings() {
    saveSettingsFile(settingsPath(), st.settings);
}

// 自启：每次开启都重写为当前 exe 绝对路径（exe 移动/改名后旧项自然失效并被纠正）。
// Windows：HKCU Run 键；Linux：XDG autostart .desktop（Exec 路径按 desktop entry
// spec 转义并整体加引号，空格路径安全）。
static void setAutostart(bool on) {
#ifdef _WIN32
    HKEY run;
    if (on) {
        wchar_t exe[MAX_PATH];
        if (!GetModuleFileNameW(nullptr, exe, MAX_PATH)) return;
        if (RegCreateKeyExW(HKEY_CURRENT_USER,
                            L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, nullptr, 0,
                            KEY_SET_VALUE, nullptr, &run, nullptr) == ERROR_SUCCESS) {
            DWORD bytes = (DWORD)((wcslen(exe) + 1) * sizeof(wchar_t));
            RegSetValueExW(run, L"onetime", 0, REG_SZ, (const BYTE*)exe, bytes);
            RegCloseKey(run);
        }
    } else if (RegOpenKeyExW(HKEY_CURRENT_USER,
                             L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE,
                             &run) == ERROR_SUCCESS) {
        RegDeleteValueW(run, L"onetime");
        RegCloseKey(run);
    }
#else
    namespace fs = std::filesystem;
    std::string exe = plat::exePathUtf8();
    if (on) {
        if (exe.empty()) return;
        std::string esc; // desktop entry 保留字转义（\ " ` $）
        for (char c : exe) {
            if (c == '\\' || c == '"' || c == '`' || c == '$') esc += '\\';
            esc += c;
        }
        std::string dir = plat::homeDirUtf8() + "/.config/autostart";
        std::error_code ec;
        fs::create_directories(fs::u8path(dir), ec);
        std::ofstream out(fs::u8path(dir + "/onetime.desktop"), std::ios::binary | std::ios::trunc);
        if (!out) return;
        out << "[Desktop Entry]\n"
            << "Type=Application\n"
            << "Name=onetime\n"
            << "Exec=\"" << esc << "\"\n"
            << "Terminal=false\n";
    } else {
        plat::removeFile(plat::homeDirUtf8() + "/.config/autostart/onetime.desktop");
    }
#endif
}

// ---------------- Agent 模板编辑与持久化（本地文件） ----------------
// 存储：~/.onetime/agent-template.{link,vault}.txt；存在即生效，删除即恢复默认。
// 与金库同目录层级（~/.onetime/），但不在 secrets/ 内，agent 无需读取。

static std::string tplPath(const char* kind) {
    std::string base = defaultVaultDir(); // …/.onetime/secrets
    auto pos = base.rfind('/');
    std::string dir = pos == std::string::npos ? std::string(".onetime") : base.substr(0, pos);
    return dir + "/agent-template." + kind + ".txt";
}

static bool readTplFile(const std::string& path, std::string& out) {
    // u8path：路径按 UTF-8 解释（非 ASCII 用户名下 ANSI 构造会失败）
    std::ifstream f(fs::u8path(path), std::ios::binary);
    if (!f) return false;
    std::ostringstream ss;
    ss << f.rdbuf();
    out = ss.str();
    return true;
}

static bool writeTplFile(const std::string& path, const std::string& data) {
    std::error_code ec;
    fs::create_directories(fs::u8path(path).parent_path(), ec);
    std::string tmp = path + ".tmp";
    {
        std::ofstream f(fs::u8path(tmp), std::ios::binary | std::ios::trunc);
        if (!f) return false;
        f.write(data.data(), (std::streamsize)data.size());
        if (!f) return false;
    }
    return plat::moveReplace(tmp, path, true);
}

static bool deleteTplFile(const std::string& path) {
    return plat::removeFile(path);
}

static std::string& tplEffective() { return st.tab == 0 ? st.tplLink : st.tplVault; }
static std::string& tplDraft() { return st.tab == 0 ? st.tplDraftLink : st.tplDraftVault; }

static void loadTemplatesFromDisk() {
    std::string raw;
    st.tplLink = readTplFile(tplPath("link"), raw) ? raw : kLinkTpl;
    st.tplVault = readTplFile(tplPath("vault"), raw) ? raw : kVaultTpl;
    st.tplDraftLink = st.tplLink;
    st.tplDraftVault = st.tplVault;
}

static void saveTemplate() {
    const char* kind = st.tab == 0 ? "link" : "vault";
    if (!writeTplFile(tplPath(kind), tplDraft())) {
        st.tplNote = "保存失败：目录不可写";
    } else {
        tplEffective() = tplDraft();
        st.tplNote = "已保存，长期生效";
    }
    st.tplNoteAt = SteadyClock::now();
}

static void resetTemplate() {
    const char* kind = st.tab == 0 ? "link" : "vault";
    deleteTplFile(tplPath(kind));
    tplEffective() = st.tab == 0 ? std::string(kLinkTpl) : std::string(kVaultTpl);
    tplDraft() = tplEffective();
    st.tplNote = "已恢复默认模板";
    st.tplNoteAt = SteadyClock::now();
}

// ---------------- 异步业务（work 在线程池，then 回 UI 线程） ----------------

struct Outcome {
    int status = 0;
    std::string link, token, expires, expireAt, err;
};

static std::string trimCr(std::string s) {
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
    return s;
}

// 金库清单按行拆分（服务端保证每行一个合法条目名）
static std::vector<std::string> parseVaultNames(const std::string& body) {
    std::vector<std::string> names;
    size_t pos = 0;
    while (pos < body.size()) {
        size_t nl = body.find('\n', pos);
        if (nl == std::string::npos) nl = body.size();
        if (nl > pos) names.push_back(body.substr(pos, nl - pos));
        pos = nl + 1;
    }
    return names;
}

static void refreshVault() {
    app::async::restart(
        "vault.list",
        [] { return httpCall(g_cli.addr, "GET", "/vault", ""); },
        [](const app::async::Result<HttpResult>& res) {
            if (res.ok && res.value.status == 200) {
                st.vaultLoaded = true; // 只有成功才置位：失败保留自动重试路径
                st.vaultNames = parseVaultNames(res.value.body);
                st.vNote.clear(); // 清掉重试成功前留下的失败提示
            } else {
                st.vNote = res.ok ? "清单拉取失败：HTTP " + std::to_string(res.value.status)
                                  : "清单拉取失败：" + res.error;
                st.vaultRetryAt = SteadyClock::now() + std::chrono::milliseconds(400);
            }
        });
}

static void startCreate() {
    std::string secret = st.secretDraft;
    std::string ttl = kTtls[st.ttlIdx];
    std::string ttlLabel = kTtlLabels[st.ttlIdx];
    app::async::restart(
        "create",
        [secret, ttl] {
            Outcome o;
            HttpResult r = httpCall(g_cli.addr, "POST", "/create?ttl=" + ttl, secret);
            o.status = r.status;
            if (r.status == 200) {
                o.link = trimCr(r.body);
                auto it = r.headers.find("x-delete-token");
                if (it != r.headers.end()) o.token = it->second;
                it = r.headers.find("x-expires-in");
                if (it != r.headers.end()) {
                    o.expires = it->second;
                    o.expireAt = expireAtFrom(strtoll(it->second.c_str(), nullptr, 10));
                }
            } else {
                o.err = r.err.empty() ? "HTTP " + std::to_string(r.status) + "：" + trimCr(r.body) : r.err;
            }
            return o;
        },
        [ttlLabel](const app::async::Result<Outcome>& res) {
            if (res.ok && res.value.status == 200) {
                st.link = res.value.link;
                st.token = res.value.token;
                st.ticketNo = ticketNoOf(st.link);
                st.expireAt = res.value.expireAt;
                st.secretDraft.clear();
                st.linkError.clear();
                pushRecord("链接", st.ticketNo, ttlLabel);
                // B1：生成后自动复制（与"仅复制链接"按钮共享反馈状态机，自然显示 1.6s"已复制"）
                if (st.settings.autoCopyLink) copyWithFeedback("copy.link", st.link);
            } else {
                st.linkError = "创建失败：" + (res.ok ? res.value.err : res.error);
            }
        });
}

static void startBurn() {
    std::string path = st.link;
    auto slash = path.rfind("/s/");
    if (slash == std::string::npos) return;
    path = path.substr(slash);
    std::string token = st.token;
    std::string no = st.ticketNo;
    app::async::restart(
        "burn",
        [path, token] {
            std::vector<std::pair<std::string, std::string>> hdrs{{"X-Delete-Token", token}};
            return httpCall(g_cli.addr, "DELETE", path, "", hdrs);
        },
        [no](const app::async::Result<HttpResult>& res) {
            if (res.ok && res.value.status == 200) {
                pushRecord("链接", no, "已作废");
                st.link.clear();
                st.token.clear();
                st.ticketNo.clear();
                st.expireAt.clear();
                showToast("已作废", "未读链接已撤回");
            } else if (res.ok && res.value.status == 404) {
                st.link.clear();
                st.token.clear();
                st.ticketNo.clear();
                st.expireAt.clear();
                showToast("作废落空", "链接已被取用或已过期");
            } else {
                showToast("作废失败", res.ok ? "HTTP " + std::to_string(res.value.status) : res.error);
            }
        });
}

static std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof buf, "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back((char)c);
                }
        }
    }
    return out;
}

static void vaultPut() {
    std::string name = std::string(trimSpace(st.vName));
    std::string secret = std::string(trimSpace(st.vSecret));
    std::string body = "{\"name\":\"" + jsonEscape(name) + "\",\"secret\":\"" + jsonEscape(secret) + "\"}";
    app::async::restart(
        "vault.put",
        [body] {
            std::vector<std::pair<std::string, std::string>> hdrs{
                {"Content-Type", "application/json"}};
            return httpCall(g_cli.addr, "POST", "/vault", body, hdrs);
        },
        [name](const app::async::Result<HttpResult>& res) {
            if (res.ok && res.value.status == 200) {
                st.vaultOkName = name;
                auto it = res.value.headers.find("x-vault-path");
                st.vaultOkDir = it != res.value.headers.end() && !it->second.empty() ? it->second
                                                                                     : g_vaultDisplay;
                auto ow = res.value.headers.find("x-overwritten");
                st.vaultOverwritten = ow != res.value.headers.end() && ow->second == "true";
                st.vSecret.clear();
                if (st.settings.clearNameAfterPut) st.vName.clear();
                st.vNote.clear();
                pushRecord("金库", name, st.vaultOverwritten ? "已覆盖" : "落盘");
                refreshVault();
            } else {
                st.vNote = res.ok ? "存入失败：HTTP " + std::to_string(res.value.status) + "：" +
                                         trimCr(res.value.body)
                                  : "存入失败：" + res.error;
            }
        });
}

static void vaultDelete(const std::string& name) {
    app::async::restart(
        "vault.del",
        [name] { return httpCall(g_cli.addr, "DELETE", "/vault?name=" + name, ""); },
        [name](const app::async::Result<HttpResult>& res) {
            if (res.ok && res.value.status == 200) {
                st.armedDelete.clear();
                pushRecord("金库", name, "已删除");
                refreshVault();
            } else {
                st.vNote = res.ok ? "删除失败：HTTP " + std::to_string(res.value.status)
                                  : "删除失败：" + res.error;
            }
        });
}

static void onDeleteClick(const std::string& name) {
    if (isArmed(name)) {
        vaultDelete(name);
    } else {
        st.armedDelete = name;
        st.armedAt = SteadyClock::now();
    }
}

// ---------------- 应用配置与入口 ----------------

// 图标：单文件分发不携带 assets/，把内嵌 PNG（icon_png.h，由 scripts/make-icon.py
// 生成）写到临时目录交给 EUI iconPath 加载；失败则静默走框架默认图标。
// Windows 的 exe/任务栏图标另有 app.rc 内嵌（GLFW 自动认领 GLFW_ICON 资源）。
std::string writeIconTempFile() {
    namespace fs = std::filesystem;
    std::error_code ec;
    fs::path p = fs::temp_directory_path(ec);
    if (ec) return {};
    p /= "onetime-icon.png";
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    if (!f) return {};
    f.write(reinterpret_cast<const char*>(kIconPng),
            static_cast<std::streamsize>(kIconPngSize));
    return f.good() ? p.string() : std::string{};
}

#ifndef _WIN32
// Linux 桌面集成：GNOME/KDE 的 dock/Alt-Tab 不读 _NET_WM_ICON，而是按 WM_CLASS
// 关联 .desktop 入口取图标。GLFW 未显式设置时 WM_CLASS 回退成窗口标题（含中文
// 与空格，无法匹配任何入口）；RESOURCE_NAME 环境变量可定 res_name（res_class
// 仍为标题，GNOME 两者任一命中即关联）。.desktop/图标自装到用户目录（单二进制
// 无包管理器，同 Chrome/VSCode 模式）。Wayland 的 app_id 只认 GLFW hint（EUI
// 未暴露），纯 Wayland 会话下 dock 图标仍为通用占位，属框架限制。
static void installDesktopEntry() {
    namespace fs = std::filesystem;
    std::error_code ec;
    const std::string home = plat::homeDirUtf8();
    if (home.empty()) return;
    const fs::path iconsDir = fs::u8path(home) / ".local/share/icons";
    fs::create_directories(iconsDir, ec);
    std::ofstream icon(iconsDir / "onetime.png", std::ios::binary | std::ios::trunc);
    if (!icon) return;
    icon.write(reinterpret_cast<const char*>(kIconPng),
               static_cast<std::streamsize>(kIconPngSize));
    icon.close();

    const std::string exe = plat::exePathUtf8();
    if (exe.empty()) return;
    std::string esc; // Exec 保留字转义（与自启动条目同规则）
    for (char c : exe) {
        if (c == '\\' || c == '"' || c == '`' || c == '$') esc += '\\';
        esc += c;
    }
    const fs::path appsDir = fs::u8path(home) / ".local/share/applications";
    fs::create_directories(appsDir, ec);
    std::ofstream out(appsDir / "onetime.desktop", std::ios::binary | std::ios::trunc);
    if (!out) return;
    out << "[Desktop Entry]\n"
        << "Type=Application\n"
        << "Name=onetime\n"
        << "Comment=一次性密钥递送\n"
        << "Exec=\"" << esc << "\"\n"
        << "Icon=onetime\n"
        << "Terminal=false\n"
        << "Categories=Utility;Security;\n"
        << "StartupWMClass=onetime\n";
}
#endif

const DslAppConfig& dslAppConfig() {
    static const DslAppConfig config = [] {
#ifndef _WIN32
        // 必须先于窗口创建（GLFW 创建窗口时读取）：res_name=onetime 供 dock/
        // Alt-Tab 关联 .desktop；再自装 .desktop 与图标（幂等，见函数注释）
        setenv("RESOURCE_NAME", "onetime", 0);
        installDesktopEntry();
#endif
        parseCli();
        // settings 合并必须先于页眉/页脚拼接与服务线程启动：默认 → settings → 命令行显式键
        loadSettingsFile(settingsPath(), g_settings);
        applySettingsToConfig(g_cli.addr, g_cli.cfg.publicBase, g_cli.cfg.vaultDir, g_settings,
                              g_cli.explicitKeys);
        g_cli.cfg.listenAddr = g_cli.addr;
        g_vaultDisplay = g_cli.cfg.vaultDir.empty() ? defaultVaultDir() : g_cli.cfg.vaultDir;
        // 展示统一用正斜杠，避免 USERPROFILE 反斜杠与目录正斜杠混排
        for (char& c : g_vaultDisplay)
            if (c == '\\') c = '/';
        // 页眉状态只拼一次，compose 直接引用；页脚地址是常量 g_projectUrl
        g_headerStatus = g_cli.addr + " · 出票仅内存 · 金库落盘本机";
        // 模板：本地文件优先，缺失用内置默认
        loadTemplatesFromDisk();
        // UI 态接管持久设置；自启开启时始终把 Run 键纠正为当前 exe 路径
        st.settings = g_settings;
        st.ttlIdx = g_settings.defaultTtlIdx;
        st.setSavedBase = st.setDraftBase = g_settings.publicBase;
        st.setSavedAddr = st.setDraftAddr = g_cli.addr;
        st.setSavedVault = st.setDraftVault = g_settings.vaultDir;
        if (g_settings.autostart) setAutostart(true);
        // 服务日志开关是启动期常量；服务线程与窗口同生命周期（分离线程），GUI 只是它的客户端
        g_cli.cfg.logToFile = g_settings.logToFile;
        std::thread([] {
            ServerConfig cfg = g_cli.cfg;
            if (!runServer(cfg, nullptr)) g_serverState = 2; // 监听失败在设置页给出可见反馈
        }).detach();

        const AppTheme& t = appTheme();
        DslAppConfig c = DslAppConfig{}
                             .title("onetime — 一次性密钥递送")
                             .pageId("onetime")
                             .windowSize(1200, 1000)
                             .uiScale(g_settings.uiScale); // 125% 为默认档：文字按比例直接栅格化，更大更锐
        c.clearColorValue = t.pageBg;
        if (const std::string icon = writeIconTempFile(); !icon.empty())
            c.iconPath(icon);
#ifdef _WIN32
        // 用系统中文字体（微软雅黑），避免随包携带 3.4 MB 字体资产
        if (std::filesystem::exists("C:/Windows/Fonts/msyh.ttc"))
            c.fonts("C:/Windows/Fonts/msyh.ttc", "C:/Windows/Fonts/msyh.ttc");
#else
        // Linux：按发行版常见位置探测 CJK 字体，命中即用；未命中走框架默认
        // 字体链（建议系统安装 fonts-noto-cjk，见 docs/linux-build.md）
        static const char* kCjkFonts[] = {
            "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
            "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc",
            "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
            "/usr/share/fonts/truetype/arphic/uming.ttc",
        };
        for (const char* p : kCjkFonts)
            if (std::filesystem::exists(p)) {
                c.fonts(p, p);
                break;
            }
#endif
#ifdef _WIN32
        // 托盘：关闭拦截/菜单由框架 runner 内建；探测失败时框架自动降级为真关闭
        // （Linux 默认不带托盘后端，构建详见 docs/linux-build.md，不启用）。
        // 托盘图标传 exe 自身路径：ExtractIconEx 提取 app.rc 内嵌的 GLFW_ICON。
        if (g_settings.minimizeToTray)
            c.tray(true).trayTitle("onetime").trayIcon(plat::exePathUtf8());
#endif
        // Ctrl+Enter：链接页快速生成 / 金库页快速存入（设置页无动作）
        c.onKeyEvent([](const eui::KeyEvent& e) {
            if (e.isDown() && e.key == core::InputKey::Enter && e.modifiers.control) {
                if (st.tab == 0) startCreate();
                else if (st.tab == 1) vaultPut();
            }
        });
        return c;
    }();
    return config;
}

// ---------------- 界面绘制小件 ----------------

static void txt(eui::Ui& ui, const std::string& id, const std::string& value, float size,
                core::Color color, const char* family = "", bool wrap = false, float maxWidth = 0.0f,
                float lineHeight = 0.0f) {
    auto b = ui.text(id).text(value).fontSize(size).color(color);
    if (family && *family) b.fontFamily(family);
    if (wrap) {
        b.wrap(true);
        if (maxWidth > 0.0f) b.maxWidth(maxWidth);
        if (lineHeight > 0.0f) b.lineHeight(lineHeight);
    }
    b.build();
}

static void spacer(eui::Ui& ui, const std::string& id) {
    ui.rect(id).size(0.0f, 1.0f).flexGrow(1.0f).color({0.0f, 0.0f, 0.0f, 0.0f}).build();
}

// 行内混排段落：多种颜色的文段合成一个自然换行的段（框架文本一段一色，没有富文本，
// 这里用 measureTextWidth 贪心断行后逐行渲染，换色处一行内并列文本节点）。
// 断词：ASCII 字母数字串不拆（Discord/agent 整词换行），汉字/标点/空格按单字断；
// 行首吞掉空格，避免换行后顶格空白。
struct RichSeg {
    std::string text;
    core::Color color;
};
struct RichRun {
    std::string s;
    core::Color c;
};

static bool sameColor(const core::Color& a, const core::Color& b) {
    return a.r == b.r && a.g == b.g && a.b == b.b && a.a == b.a;
}

// 断行结果缓存：compose 在票据存在期间被键入/timer 高频触发，而断行输入
// （文本/颜色/宽度/字号/行高）几乎不变——未命中才分词+测量（测量对每个
// token 从行首量整行，是 O(n²) 字形测量）。只在 UI 线程的 compose 读写，无需锁。
struct RichWrapCache {
    std::vector<RichSeg> input;
    float w = 0.0f, fontSize = 0.0f, lineHeight = 0.0f;
    std::vector<std::vector<RichRun>> lines;
    bool match(const std::vector<RichSeg>& in, float w_, float fs, float lh) const {
        if (w != w_ || fontSize != fs || lineHeight != lh || input.size() != in.size())
            return false;
        for (size_t i = 0; i < in.size(); ++i)
            if (input[i].text != in[i].text || !sameColor(input[i].color, in[i].color))
                return false;
        return true;
    }
};
static std::unordered_map<std::string, RichWrapCache> g_richCache;

static std::vector<std::vector<RichRun>> wrapRichSegments(const std::vector<RichSeg>& segs,
                                                          float w, float fontSize) {
    struct Tok {
        std::string s;
        core::Color c;
        bool space;
    };
    std::vector<Tok> toks;
    for (const RichSeg& seg : segs) {
        std::string word;
        for (char ch : seg.text) {
            if (std::isalnum((unsigned char)ch)) {
                word += ch;
                continue;
            }
            if (!word.empty()) {
                toks.push_back({word, seg.color, false});
                word.clear();
            }
            toks.push_back({std::string(1, ch), seg.color, ch == ' '});
        }
        if (!word.empty()) toks.push_back({word, seg.color, false});
    }

    std::vector<std::vector<RichRun>> lines(1);
    std::string lineText; // 当前行已装文字，量宽用
    for (const Tok& tok : toks) {
        if (lines.back().empty() && tok.space) continue;
        if (!lineText.empty() &&
            core::TextPrimitive::measureTextWidth(lineText + tok.s, "", fontSize) > w) {
            lines.emplace_back();
            lineText.clear();
            if (tok.space) continue;
        }
        if (!lines.back().empty() && sameColor(lines.back().back().c, tok.c))
            lines.back().back().s += tok.s;
        else
            lines.back().push_back({tok.s, tok.c});
        lineText += tok.s;
    }
    while (lines.size() > 1 && lines.back().empty()) lines.pop_back();
    return lines;
}

static void richParagraph(eui::Ui& ui, const std::string& id, float w, float fontSize,
                          float lineHeight,
                          const std::vector<std::pair<std::string, core::Color>>& segments) {
    std::vector<RichSeg> segs;
    segs.reserve(segments.size());
    for (const auto& s : segments) segs.push_back({s.first, s.second});
    RichWrapCache& cache = g_richCache[id];
    if (!cache.match(segs, w, fontSize, lineHeight)) {
        cache.input = std::move(segs);
        cache.w = w;
        cache.fontSize = fontSize;
        cache.lineHeight = lineHeight;
        cache.lines = wrapRichSegments(cache.input, w, fontSize);
    }
    const std::vector<std::vector<RichRun>>& lines = cache.lines;

    ui.column(id)
        .width(w)
        .height(eui::SizeValue::wrapContent())
        .gap(0.0f)
        .content([&] {
            for (size_t i = 0; i < lines.size(); ++i) {
                std::string rowId = id + ".l" + std::to_string(i);
                ui.row(rowId)
                    .size(w, lineHeight)
                    .gap(0.0f)
                    .alignItems(core::Align::CENTER)
                    .content([&] {
                        for (size_t j = 0; j < lines[i].size(); ++j)
                            txt(ui, rowId + ".r" + std::to_string(j), lines[i][j].s, fontSize,
                                lines[i][j].c);
                    })
                    .build();
            }
        })
        .build();
}

static void hairline(eui::Ui& ui, const std::string& id, float width, core::Color color) {
    ui.rect(id).size(width, 1.0f).color(color).build();
}

static void fieldHead(eui::Ui& ui, const AppTheme& t, const std::string& id,
                      const std::string& label, const std::string& hint, float w) {
    ui.row(id)
        .size(w, 18.0f)
        .alignItems(core::Align::CENTER)
        .content([&] {
            txt(ui, id + ".l", label, 13.5f, t.ink2);
            spacer(ui, id + ".sp");
            if (!hint.empty()) txt(ui, id + ".h", hint, 12.5f, t.dim, "monospace");
        })
        .build();
}

// 票据打孔分隔线：两端打孔圆点 + 中间虚线
static void perforation(eui::Ui& ui, const AppTheme& t, const std::string& id, float width) {
    ui.row(id)
        .size(width, 9.0f)
        .alignItems(core::Align::CENTER)
        .gap(7.0f)
        .content([&] {
            ui.rect(id + ".p0")
                .size(9.0f, 9.0f)
                .radius(4.5f)
                .color(t.pageBg)
                .border(1.0f, t.hair)
                .build();
            const int n = (int)((width - 32.0f) / 13.0f); // 2 端圆点 + n 段虚线 + n+1 个 gap
            for (int i = 0; i < n; ++i) {
                ui.rect(id + ".d" + std::to_string(i)).size(6.0f, 1.0f).color(t.hair).build();
            }
            ui.rect(id + ".p1")
                .size(9.0f, 9.0f)
                .radius(4.5f)
                .color(t.pageBg)
                .border(1.0f, t.hair)
                .build();
        })
        .build();
}

// ---------------- 按钮语义分级（主操作 / 次操作 / 作废 / 两步确认） ----------------

enum class BtnKind { Primary, Wash, Ghost, DangerGhost, DangerSolid, Flat };

static components::ButtonStyle btnStyle(const AppTheme& t, BtnKind kind) {
    components::ButtonStyle s;
    const core::Color black{0.0f, 0.0f, 0.0f, 1.0f};
    switch (kind) {
        case BtnKind::Primary: // 实心青绿
            s.normal = t.tokens.primary;
            s.hover = t.accentDeep;
            s.pressed = core::mixColor(t.accentDeep, black, 0.18f);
            s.text = {1.0f, 1.0f, 1.0f, 1.0f};
            s.border = {1.0f, t.tokens.primary};
            break;
        case BtnKind::Wash: // 洗底主操作（票据上的主按钮）
            s.normal = t.accentWash;
            s.hover = core::mixColor(t.accentWash, t.tokens.primary, 0.10f);
            s.pressed = t.tokens.surfaceActive;
            s.text = t.accentDeep;
            s.border = {1.0f, t.tokens.primary};
            break;
        case BtnKind::Ghost: // 白底描边
            s.normal = t.tokens.surface;
            s.hover = t.accentWash;
            s.pressed = t.tokens.surfaceActive;
            s.text = t.tokens.text;
            s.border = {1.0f, t.hair};
            break;
        case BtnKind::DangerGhost: // 砖红描边
            s.normal = t.tokens.surface;
            s.hover = t.warnWash;
            s.pressed = core::mixColor(t.warnWash, t.warn, 0.15f);
            s.text = t.warn;
            s.border = {1.0f, t.warn};
            break;
        case BtnKind::DangerSolid: // 砖红实心（两步确认武装态）
            s.normal = t.warn;
            s.hover = core::mixColor(t.warn, black, 0.12f);
            s.pressed = core::mixColor(t.warn, black, 0.22f);
            s.text = {1.0f, 1.0f, 1.0f, 1.0f};
            s.border = {1.0f, t.warn};
            break;
        case BtnKind::Flat: // 无底透明（模板折叠开关）
            s.normal = {0.0f, 0.0f, 0.0f, 0.0f};
            s.hover = t.accentWash;
            s.pressed = t.tokens.surfaceActive;
            s.text = t.ink2;
            s.border = {1.0f, {0.0f, 0.0f, 0.0f, 0.0f}};
            break;
    }
    s.icon = s.text;
    s.shadow = core::Shadow{}; // 按钮全部扁平无阴影
    s.radius = 5.0f;
    return s;
}

static void btn(eui::Ui& ui, const AppTheme& t, const std::string& id, float w, float h,
                const std::string& label, BtnKind kind, bool disabled,
                std::function<void()> onClick) {
    components::button(ui, id)
        .size(w, h)
        .text(label)
        .fontSize(14.0f)
        .style(btnStyle(t, kind))
        .opacity(disabled ? 0.55f : 1.0f) // 禁用态视觉：opacity .55
        .disabled(disabled)
        .onClick(std::move(onClick))
        .build();
}

// 页签（白底描边、选中青绿填充，未选中态用实线描边增强区分）
static void segmented(eui::Ui& ui, const AppTheme& t, const std::string& id,
                      std::initializer_list<std::string> items, int selected, float fontSize,
                      float w, float h, std::function<void(int)> onChange) {
    components::SegmentedStyle s(t.tokens);
    s.border = t.hair; // 实线描边，避免未选中页签与输入框混淆
    components::segmented(ui, id)
        .items(items)
        .selected(selected)
        .fontSize(fontSize)
        .style(s)
        .size(w, h)
        .onChange(std::move(onChange))
        .build();
}

static components::InputStyle inputStyle(const AppTheme& t) {
    components::InputStyle s(t.tokens);
    s.radius = 6.0f;
    s.border = components::theme::withOpacity(t.hair, 0.95f);
    s.focusBorder = components::theme::withAlpha(t.tokens.primary, 0.9f);
    s.placeholder = t.dim;
    return s;
}

static components::InputStyle linkWellStyle(const AppTheme& t) {
    components::InputStyle s = inputStyle(t);
    s.background = t.linkWell;
    s.focused = t.linkWell;
    s.text = t.accentDeep;
    s.cursor = t.tokens.primary;
    s.border = t.hairSoft;
    s.radius = 4.0f;
    return s;
}

// 输入框（统一浅色纸面样式）；onEnter：单行框 Enter/(Ctrl+)Enter 提交（EUI-NEO 语义：
// Enter 在输入框内被组件消费，应用级 onKeyEvent 收不到，表单快捷提交必须走此回调）
static void input(eui::Ui& ui, const AppTheme& t, const std::string& id, float w, float h,
                  const std::string& value, const std::string& placeholder, bool mono,
                  bool multiline, float fontSize,
                  std::function<void(const std::string&)> onChange,
                  const components::InputStyle* styleOverride = nullptr,
                  std::function<void()> onEnter = nullptr) {
    components::InputStyle s = styleOverride ? *styleOverride : inputStyle(t);
    components::input(ui, id)
        .theme(t.tokens)
        .style(s)
        .size(w, h)
        .value(value)
        .placeholder(placeholder)
        .fontSize(fontSize)
        .fontFamily(mono ? "monospace" : "")
        .multiline(multiline)
        .onChange(std::move(onChange))
        .onEnter(std::move(onEnter))
        .build();
}

// ---------------- 界面：链接页 ----------------

static void composeLinkPage(eui::Ui& ui, const AppTheme& t, float w) {
    ui.column("link.page")
        .width(w)
        .height(eui::SizeValue::wrapContent())
        .gap(14.0f)
        .content([&] {
            fieldHead(ui, t, "link.head", "密钥内容", "Enter 换行", w);
            input(ui, t, "link.secret", w, 64.0f, st.secretDraft,
                  "粘贴 API key、token 或任意敏感文本", true, true, 14.5f,
                  [](const std::string& v) { st.secretDraft = v; });

            ui.row("link.ctl")
                .size(w, 44.0f)
                .gap(14.0f)
                .alignItems(core::Align::CENTER)
                .content([&] {
                    segmented(ui, t, "link.ttl",
                              {kTtlLabels[0], kTtlLabels[1], kTtlLabels[2], kTtlLabels[3],
                               kTtlLabels[4]},
                              st.ttlIdx, 14.0f, 320.0f, 42.0f,
                              [](int i) { st.ttlIdx = i; });
                    spacer(ui, "link.ctl.sp");
                    btn(ui, t, "link.go", 180.0f, 44.0f,
                        app::async::running("create") ? "生成中…" : "生成一次性链接",
                        BtnKind::Primary, st.secretDraft.empty() || app::async::running("create"),
                        [] { startCreate(); });
                })
                .build();

            if (!st.linkError.empty()) {
                txt(ui, "link.error", st.linkError, 13.5f, t.warn, "", true, w, 20.0f);
            }

            // ---- 票据：生成成功后出现 ----
            if (!st.link.empty()) {
                const float cw = w - 32.0f;
                components::InputStyle well = linkWellStyle(t);
                components::card(ui, "link.ticket")
                    .theme(t.tokens)
                    .width(w)
                    .wrapContentHeight()
                    .padding(16.0f)
                    .radius(6.0f)
                    .border(1.0f, t.hair)
                    .shadow(core::Shadow{})
                    .content([&] {
                        ui.column("link.ticket.col")
                            .width(cw)
                            .height(eui::SizeValue::wrapContent())
                            .gap(10.0f)
                            .content([&] {
                                ui.row("link.ticket.head")
                                    .size(cw, 20.0f)
                                    .alignItems(core::Align::CENTER)
                                    .content([&] {
                                        txt(ui, "link.ticket.no", "NO. " + st.ticketNo, 14.0f,
                                            t.tokens.primary, "monospace");
                                        spacer(ui, "link.ticket.head.sp");
                                        if (!st.expireAt.empty())
                                            txt(ui, "link.ticket.exp", st.expireAt, 12.5f, t.dim,
                                                "monospace");
                                    })
                                    .build();

                                perforation(ui, t, "link.ticket.perfo", cw);

                                input(ui, t, "link.ticket.link", cw, 44.0f, st.link, "", true,
                                      false, 14.0f,
                                      [](const std::string& v) { st.link = v; }, &well);

                                ui.row("link.ticket.ops")
                                    .size(cw, 44.0f)
                                    .gap(10.0f)
                                    .content([&] {
                                        btn(ui, t, "link.copytpl", 160.0f, 44.0f,
                                            copyLabel("copy.agent", "复制给 Agent", "已复制给 Agent"),
                                            BtnKind::Wash, false,
                                            [] { copyWithFeedback("copy.agent", substitute(st.tplLink, "{link}", st.link)); });
                                        btn(ui, t, "link.copy", 128.0f, 44.0f,
                                            copyLabel("copy.link", "仅复制链接", "已复制"),
                                            BtnKind::Ghost, false,
                                            [] { copyWithFeedback("copy.link", st.link); });
                                        btn(ui, t, "link.burn", 128.0f, 44.0f,
                                            app::async::running("burn") ? "作废中…" : "作废此链接",
                                            BtnKind::DangerGhost, app::async::running("burn"),
                                            [] { startBurn(); });
                                    })
                                    .build();

                                // 一段话两种颜色：灰句紧接警告句末尾续排（行内混排）
                                richParagraph(ui, "link.ticket.notes", cw, 13.0f, 20.0f, {
                                    {"链接即凭证：取一次即失效，勿打开测试；只经无预览通道（终端/"
                                     "agent 会话），Discord、Slack 等会预取，预览即取走明文并烧毁。",
                                     t.warn},
                                    {"作废令牌仅存本窗口内存，关窗后只能等过期。", t.dim},
                                });
                            })
                            .build();
                    })
                    .build();
            }
        })
        .build();
}

// ---------------- 界面：金库页 ----------------

static void composeVaultPage(eui::Ui& ui, const AppTheme& t, float w) {
    // 初始加载的自动触发：in-flight 去重 + 失败 400ms 退避（服务刚启动的几百毫秒
    // 窗口期内，不再每次 compose 都 cancel+repost）；监听彻底失败（状态 2）不重试。
    // 手动刷新（存入/删除/切页）走 refreshVault 的 restart，不受此守卫约束。
    if (!st.vaultLoaded && g_serverState != 2 &&
        !app::async::running("vault.list") && SteadyClock::now() >= st.vaultRetryAt)
        refreshVault();

    ui.column("vault.page")
        .width(w)
        .height(eui::SizeValue::wrapContent())
        .gap(14.0f)
        .content([&] {
            fieldHead(ui, t, "vault.head", "密钥内容（将写入本机金库，单行）",
                      "<= 4096 bytes · Enter 存入", w);
            ui.row("vault.form")
                .size(w, 44.0f)
                .gap(10.0f)
                .content([&] {
                    input(ui, t, "vault.name", 210.0f, 44.0f, st.vName, "KEY 名称，如 GITHUB_TOKEN",
                          true, false, 14.5f, [](const std::string& v) { st.vName = v; }, nullptr,
                          [] { vaultPut(); });
                    input(ui, t, "vault.secret", w - 210.0f - 10.0f - 140.0f - 10.0f, 44.0f,
                          st.vSecret, "密钥值（单行）", true, false, 14.5f,
                          [](const std::string& v) { st.vSecret = v; }, nullptr,
                          [] { vaultPut(); });
                    btn(ui, t, "vault.put", 140.0f, 44.0f,
                        app::async::running("vault.put") ? "写入中…" : "存入金库", BtnKind::Primary,
                        st.vName.empty() || st.vSecret.empty() || app::async::running("vault.put"),
                        [] { vaultPut(); });
                })
                .build();

            if (!st.vNote.empty()) {
                txt(ui, "vault.note", st.vNote, 13.5f, t.warn, "", true, w, 20.0f);
            }

            // ---- 票据：存入成功 ----
            if (!st.vaultOkName.empty()) {
                const float cw = w - 32.0f;
                components::card(ui, "vault.ok")
                    .theme(t.tokens)
                    .width(w)
                    .wrapContentHeight()
                    .padding(16.0f)
                    .radius(6.0f)
                    .border(1.0f, t.hair)
                    .shadow(core::Shadow{})
                    .content([&] {
                        ui.column("vault.ok.col")
                            .width(cw)
                            .height(eui::SizeValue::wrapContent())
                            .gap(10.0f)
                            .content([&] {
                                ui.row("vault.ok.head")
                                    .size(cw, 20.0f)
                                    .alignItems(core::Align::CENTER)
                                    .content([&] {
                                        txt(ui, "vault.ok.tag",
                                            st.vaultOverwritten ? "已覆盖金库条目" : "已存入金库",
                                            14.0f, t.tokens.primary, "monospace");
                                        spacer(ui, "vault.ok.head.sp");
                                        txt(ui, "vault.ok.dir", st.vaultOkDir, 12.0f, t.dim,
                                            "monospace");
                                    })
                                    .build();

                                perforation(ui, t, "vault.ok.perfo", cw);

                                txt(ui, "vault.ok.body",
                                    std::string(st.vaultOverwritten
                                                    ? "同名旧值已被这次的内容整体替换（不可恢复）——"
                                                    : "") +
                                        "密钥已以 " + st.vaultOkName +
                                        " 写入本机金库，对话与 agent 递送环节全程未经过它。需要使用时"
                                        "直接告诉 agent 名字即可。",
                                    13.0f, t.ink2, "", true, cw, 19.0f);

                                {
                                    std::string names;
                                    for (size_t i = 0; i < st.vaultNames.size(); ++i) {
                                        if (i) names += "、";
                                        names += st.vaultNames[i];
                                    }
                                    if (!names.empty())
                                        txt(ui, "vault.ok.names", "金库现有：" + names, 13.0f,
                                            t.ink2, "monospace", true, cw, 18.0f);
                                }

                                ui.row("vault.ok.ops")
                                    .size(cw, 44.0f)
                                    .content([&] {
                                        btn(ui, t, "vault.copytpl", 160.0f, 44.0f,
                                            copyLabel("copy.vault", "复制给 Agent", "已复制给 Agent"),
                                            BtnKind::Wash, false,
                                            [] { copyWithFeedback("copy.vault", substitute(st.tplVault, "{name}", st.vaultOkName)); });
                                    })
                                    .build();

                                txt(ui, "vault.ok.warn",
                                    "金库条目是明文本机文件（~/.onetime/secrets/<名字>），受本机登录权限"
                                    "保护。定期轮换密钥，不要把该目录提交进任何仓库。",
                                    13.0f, t.warn, "", true, cw, 20.0f);
                            })
                            .build();
                    })
                    .build();
            }

            // ---- 金库条目管理（两步确认删除） ----
            ui.column("vault.manage")
                .width(w)
                .height(eui::SizeValue::wrapContent())
                .gap(12.0f)
                .content([&] {
                    fieldHead(ui, t, "vault.manage.head", "金库条目", "", w);
                    hairline(ui, "vault.manage.line", w, t.hair);

                    if (st.vaultNames.empty()) {
                        txt(ui, "vault.empty", "金库为空。贴入第一条即创建目录，或直接在金库目录下"
                                                "增删条目文件。",
                            13.5f, t.dim, "", true, w, 20.0f);
                    } else {
                        // 条目清单自成一个 gap=0 子列，行间靠发丝线分隔，不吃外层的 12 间距
                        ui.column("vault.list")
                            .width(w)
                            .height(eui::SizeValue::wrapContent())
                            .gap(0.0f)
                            .content([&] {
                                for (size_t i = 0; i < st.vaultNames.size(); ++i) {
                                    const std::string& name = st.vaultNames[i];
                                    std::string rowId = "vault.row." + std::to_string(i);
                                    ui.row(rowId)
                                        .size(w, 38.0f)
                                        .alignItems(core::Align::CENTER)
                                        .gap(10.0f)
                                        .content([&] {
                                            txt(ui, rowId + ".name", name, 14.5f, t.ink2,
                                                "monospace");
                                            spacer(ui, rowId + ".sp");
                                            btn(ui, t, rowId + ".tpl", 162.0f, 30.0f,
                                                copyLabel("copy.vaulttpl." + name,
                                                          "复制给 Agent", "已复制"),
                                                BtnKind::Ghost, false, [name] {
                                                    copyWithFeedback(
                                                        "copy.vaulttpl." + name,
                                                        substitute(st.tplVault, "{name}", name));
                                                });
                                            bool armed = isArmed(name);
                                            bool busy = app::async::running("vault.del");
                                            if (armed) {
                                                btn(ui, t, rowId + ".del", 104.0f, 30.0f,
                                                    "确认删除", BtnKind::DangerSolid, busy,
                                                    [name] { onDeleteClick(name); });
                                            } else {
                                                btn(ui, t, rowId + ".del", 80.0f, 30.0f, "删除",
                                                    BtnKind::DangerGhost, busy,
                                                    [name] { onDeleteClick(name); });
                                            }
                                        })
                                        .build();
                                    if (i + 1 < st.vaultNames.size()) {
                                        hairline(ui, rowId + ".line", w, t.hairSoft);
                                    }
                                }
                            })
                            .build();

                        // 删除两步确认的说明只在有条目时出现，空库不堆提示文字
                        txt(ui, "vault.manage.hint",
                            "删除需两步确认：点一下变「确认删除」，3 秒内再点生效；agent 正在使用的"
                            "条目删除前先和它打好招呼。",
                            13.5f, t.dim, "", true, w, 20.0f);
                    }
                })
                .build();
        })
        .build();
}

// ---------------- 界面：Agent 说明模板面板（编辑 + 保存/恢复） ----------------

static void composeTplPanel(eui::Ui& ui, const AppTheme& t, float w) {
    ui.column("tpl.panel")
        .width(w)
        .height(eui::SizeValue::wrapContent())
        .gap(8.0f)
        .content([&] {
            hairline(ui, "tpl.panel.top", w, t.hair);
            btn(ui, t, "tpl.toggle", 230.0f, 32.0f,
                st.tplEditOpen ? "- 收起 Agent 说明模板" : "+ 给 Agent 的说明模板",
                BtnKind::Ghost, false, [] { st.tplEditOpen = !st.tplEditOpen; });
            txt(ui, "tpl.hint",
                st.tab == 0 ? "决定一次性链接模式下\"复制给 Agent\"按钮产出的文字。支持 {link} 占位符，"
                              "点击复制时自动替换为链接；改完点保存，长期生效。"
                            : "决定本机金库模式下\"复制给 Agent\"按钮产出的文字。支持 {name} 占位符，"
                              "点击复制时自动替换为条目名；改完点保存，长期生效。",
                13.5f, t.dim, "", true, w, 19.0f);
            if (!st.tplEditOpen) return;

            input(ui, t, "tpl.edit", w, 160.0f, tplDraft(), "", true, true, 14.0f,
                  [](const std::string& v) { tplDraft() = v; });

            ui.row("tpl.ops")
                .size(w, 32.0f)
                .gap(10.0f)
                .content([&] {
                    btn(ui, t, "tpl.save", 104.0f, 32.0f, "保存模板", BtnKind::Primary, false,
                        [] { saveTemplate(); });
                    btn(ui, t, "tpl.reset", 118.0f, 32.0f, "恢复默认", BtnKind::Ghost, false,
                        [] { resetTemplate(); });
                    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        SteadyClock::now() - st.tplNoteAt);
                    if (!st.tplNote.empty() && ms.count() < 2400)
                        txt(ui, "tpl.note", st.tplNote, 13.0f, t.tokens.primary);
                })
                .build();
        })
        .build();
}

// ---------------- 界面：会话记录 + 页脚 ----------------

static void composeRecords(eui::Ui& ui, const AppTheme& t, float w) {
    ui.column("records")
        .width(w)
        .height(eui::SizeValue::wrapContent())
        .gap(8.0f)
        .content([&] {
            hairline(ui, "records.top", w, t.hair);
            txt(ui, "records.label", "本会话记录", 13.0f, t.ink2);

            if (st.records.empty()) {
                txt(ui, "records.empty", "本次会话还没有操作记录。记录只保存在当前窗口，关闭即清空。",
                    13.5f, t.dim);
                return;
            }
            for (size_t i = 0; i < st.records.size(); ++i) {
                const SessionRecord& r = st.records[i];
                std::string rowId = "record." + std::to_string(i);
                ui.row(rowId)
                    .size(w, 28.0f)
                    .alignItems(core::Align::CENTER)
                    .gap(10.0f)
                    .content([&] {
                        txt(ui, rowId + ".time", r.time, 13.0f, t.dim, "monospace");
                        txt(ui, rowId + ".kind", "[" + r.kind + "]", 12.5f, t.dim);
                        txt(ui, rowId + ".no", r.no, 13.5f, t.tokens.primary, "monospace");
                        spacer(ui, rowId + ".sp");
                        txt(ui, rowId + ".tag", r.tag, 12.5f, t.dim);
                    })
                    .build();
            }
        })
        .build();
}

// ---------------- 界面：设置页（服务与链接 / 行为 / 外观 / 运维 四区） ----------------

static void saveServiceText() {
    std::string base = stripTrailingSlash(std::string(trimSpace(st.setDraftBase)));
    std::string addr = std::string(trimSpace(st.setDraftAddr));
    std::string vault = std::string(trimSpace(st.setDraftVault));
    if (!addr.empty() && !validHostPort(addr)) {
        st.setNote = "监听地址格式应为 host:port，如 127.0.0.1:8787";
        return;
    }
    st.settings.publicBase = base;
    st.settings.listenAddr = addr;
    st.settings.vaultDir = vault;
    persistSettings();
    st.setDraftBase = st.setSavedBase = base;
    st.setDraftAddr = st.setSavedAddr = addr;
    st.setDraftVault = st.setSavedVault = vault;
    st.tplNote = "已保存，下次启动生效";
}

// 文本设置行：标签 + 输入框 + 保存按钮（保存按钮仅在该行有改动时可用；Enter 同保存）
static void settingsTextRow(eui::Ui& ui, const AppTheme& t, const std::string& id,
                            const std::string& label, float w, std::string& draft,
                            const std::string& saved, const std::string& placeholder) {
    fieldHead(ui, t, id + ".head", label, "", w);
    ui.row(id + ".row")
        .size(w, 40.0f)
        .gap(10.0f)
        .alignItems(core::Align::CENTER)
        .content([&] {
            input(ui, t, id + ".in", w - 116.0f, 38.0f, draft, placeholder, false, false, 14.0f,
                  [&draft](const std::string& v) { draft = v; }, nullptr, [] { saveServiceText(); });
            btn(ui, t, id + ".save", 96.0f, 38.0f, "保存", BtnKind::Primary, draft == saved,
                [] { saveServiceText(); });
        })
        .build();
}

// 开关行（EUI-NEO toggleSwitch 自带标签；无 disabled 能力，不可用项直接不渲染该行）
static void sw(eui::Ui& ui, const AppTheme& t, const std::string& id, const std::string& label,
               bool checked, float w, std::function<void(bool)> onChange) {
    components::toggleSwitch(ui, id)
        .text(label)
        .checked(checked)
        .fontSize(13.5f)
        .theme(t.tokens)
        .size(w, 40.0f)
        .onChange(std::move(onChange))
        .build();
}

// 用系统默认浏览器打开外链（页脚项目地址）；URL 是纯 ASCII，宽窄转换安全
static void openInBrowser(const char* url) {
#ifdef _WIN32
    std::string narrow(url);
    std::wstring wide(narrow.begin(), narrow.end());
    ShellExecuteW(nullptr, L"open", wide.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
#else
    // xdg-open 拉起默认浏览器；收尸放分离线程——generic 回退路径可能 exec
    // 浏览器本体或弹选择框，同步 waitpid 会挂住 UI 线程
    pid_t pid = 0;
    char* argv[] = {(char*)"xdg-open", (char*)url, nullptr};
    if (posix_spawnp(&pid, "xdg-open", nullptr, nullptr, argv, environ) == 0)
        std::thread([pid] { waitpid(pid, nullptr, 0); }).detach();
#endif
}

static void composeSettingsPage(eui::Ui& ui, const AppTheme& t, float w) {
    ui.column("set.page")
        .width(w)
        .height(eui::SizeValue::wrapContent())
        .gap(20.0f)
        .content([&] {
            if (!st.tplNote.empty())
                txt(ui, "set.note", st.tplNote, 13.5f, t.tokens.primary, "", true, w, 19.0f);
            if (!st.setNote.empty())
                txt(ui, "set.warn", st.setNote, 13.5f, t.warn, "", true, w, 19.0f);

            // ---- 服务与链接 ----
            ui.column("set.svc")
                .width(w)
                .height(eui::SizeValue::wrapContent())
                .gap(12.0f)
                .content([&] {
                    fieldHead(ui, t, "set.svc.head", "服务与链接", "", w);
                    hairline(ui, "set.svc.line", w, t.hair);
                    if (g_serverState == 2)
                        txt(ui, "set.svc.state",
                            "服务启动失败：监听地址可能被占用，请修改后重启应用", 13.5f, t.warn,
                            "", true, w, 19.0f);
                    else
                        txt(ui, "set.svc.state", "服务运行中 · 监听 " + g_cli.addr, 12.5f, t.dim,
                            "monospace");

                    ui.row("set.svc.ttl")
                        .size(w, 40.0f)
                        .alignItems(core::Align::CENTER)
                        .content([&] {
                            txt(ui, "set.svc.ttl.l", "默认有效期", 13.5f, t.ink2);
                            spacer(ui, "set.svc.ttl.sp");
                            segmented(ui, t, "set.svc.ttl.sel", {"30m", "1h", "8h", "24h", "7d"},
                                      st.settings.defaultTtlIdx, 13.0f, 236.0f, 34.0f, [](int i) {
                                          st.settings.defaultTtlIdx = i;
                                          st.ttlIdx = i;
                                          persistSettings();
                                      });
                        })
                        .build();

                    settingsTextRow(ui, t, "set.svc.base", "公共链接前缀（重启生效）", w,
                                    st.setDraftBase, st.setSavedBase, "https://密钥服务对外地址/");
                    settingsTextRow(ui, t, "set.svc.addr", "监听地址（重启生效）", w,
                                    st.setDraftAddr, st.setSavedAddr, "127.0.0.1:8787");
                    settingsTextRow(ui, t, "set.svc.vault", "金库目录（重启生效）", w,
                                    st.setDraftVault, st.setSavedVault, "C:/Users/me/.onetime/secrets");
                    txt(ui, "set.svc.hint",
                        "本区修改保存后，下次启动应用时生效；留空恢复默认。公共链接前缀为空时按请求 "
                        "Host 推导，反向代理或对外分发时填写。金库目录切换不会移动旧文件。",
                        13.5f, t.dim, "", true, w, 19.0f);
                })
                .build();

            // ---- 行为 ----
            ui.column("set.beh")
                .width(w)
                .height(eui::SizeValue::wrapContent())
                .gap(10.0f)
                .content([&] {
                    fieldHead(ui, t, "set.beh.head", "行为", "", w);
                    hairline(ui, "set.beh.line", w, t.hair);
                    sw(ui, t, "set.beh.autocopy", "生成链接后自动复制到剪贴板",
                       st.settings.autoCopyLink, w, [](bool v) {
                           st.settings.autoCopyLink = v;
                           persistSettings();
                       });
                    sw(ui, t, "set.beh.clearname", "存入金库后清空名称框",
                       st.settings.clearNameAfterPut, w, [](bool v) {
                           st.settings.clearNameAfterPut = v;
                           persistSettings();
                       });
                    sw(ui, t, "set.beh.showrec", "显示本会话记录", st.settings.showRecords, w,
                       [](bool v) {
                           st.settings.showRecords = v;
                           persistSettings();
                       });
                    ui.row("set.beh.clearrow")
                        .size(w, 38.0f)
                        .alignItems(core::Align::CENTER)
                        .gap(10.0f)
                        .content([&] {
                            txt(ui, "set.beh.clearl", "清空本会话记录", 13.5f, t.ink2);
                            spacer(ui, "set.beh.clearsp");
                            bool armed = isArmed("session-records");
                            if (armed) {
                                btn(ui, t, "set.beh.clear", 104.0f, 30.0f, "确认清空",
                                    BtnKind::DangerSolid, false, [] {
                                        st.records.clear();
                                        st.armedDelete.clear();
                                        st.tplNote = "会话记录已清空";
                                    });
                            } else {
                                btn(ui, t, "set.beh.clear", 90.0f, 30.0f, "清空记录",
                                    BtnKind::DangerGhost, false, [] {
                                        st.armedDelete = "session-records";
                                        st.armedAt = SteadyClock::now();
                                    });
                            }
                        })
                        .build();
                })
                .build();

            // ---- 外观 ----
            ui.column("set.look")
                .width(w)
                .height(eui::SizeValue::wrapContent())
                .gap(10.0f)
                .content([&] {
                    fieldHead(ui, t, "set.look.head", "外观", "", w);
                    hairline(ui, "set.look.line", w, t.hair);
                    ui.row("set.look.theme")
                        .size(w, 40.0f)
                        .alignItems(core::Align::CENTER)
                        .content([&] {
                            txt(ui, "set.look.theme.l", "主题（重启生效）", 13.5f, t.ink2);
                            spacer(ui, "set.look.theme.sp");
                            segmented(ui, t, "set.look.theme.sel", {"浅色", "深色"},
                                      st.settings.darkTheme ? 1 : 0, 13.0f, 130.0f, 34.0f,
                                      [](int i) {
                                          st.settings.darkTheme = i == 1;
                                          persistSettings();
                                          st.tplNote = "主题已保存，重启后生效";
                                      });
                        })
                        .build();
                    ui.row("set.look.scale")
                        .size(w, 40.0f)
                        .alignItems(core::Align::CENTER)
                        .content([&] {
                            txt(ui, "set.look.scale.l", "界面缩放（重启生效）", 13.5f, t.ink2);
                            spacer(ui, "set.look.scale.sp");
                            int idx = st.settings.uiScale == 1.0f   ? 0
                                      : st.settings.uiScale == 1.5f ? 2
                                                                    : 1;
                            segmented(ui, t, "set.look.scale.sel", {"100%", "125%", "150%"}, idx,
                                      13.0f, 190.0f, 34.0f, [](int i) {
                                          st.settings.uiScale = i == 0   ? 1.0f
                                                                : i == 2 ? 1.5f
                                                                         : 1.25f;
                                          persistSettings();
                                          st.tplNote = "缩放已保存，重启后生效";
                                      });
                        })
                        .build();
                    sw(ui, t, "set.look.autostart", "开机自启动", st.settings.autostart, w,
                       [](bool v) {
                           st.settings.autostart = v;
                           persistSettings();
                           setAutostart(v);
                       });
#ifdef _WIN32
                    // Linux 无托盘后端（默认构建）时隐藏该开关，避免误导；
                    // 设置文件里已有值保留不生效，拷回 Windows 仍然有效
                    sw(ui, t, "set.look.tray", "关闭窗口时最小化到托盘（重启生效）",
                       st.settings.minimizeToTray, w, [](bool v) {
                           st.settings.minimizeToTray = v;
                           persistSettings();
                       });
#endif
                })
                .build();

            // ---- 运维 ----
            ui.column("set.ops")
                .width(w)
                .height(eui::SizeValue::wrapContent())
                .gap(10.0f)
                .content([&] {
                    fieldHead(ui, t, "set.ops.head", "运维", "", w);
                    hairline(ui, "set.ops.line", w, t.hair);
                    sw(ui, t, "set.ops.logfile", "服务日志落盘（重启生效）", st.settings.logToFile,
                       w, [](bool v) {
                           st.settings.logToFile = v;
                           persistSettings();
                       });
                    txt(ui, "set.ops.loghint",
                        "日志零泄密：只记事件与字节数，绝不记密钥材料。落盘到 "
                        "~/.onetime/service.log，超过 1 MiB 启动时自动轮转。",
                        13.5f, t.dim, "", true, w, 19.0f);
                    ui.row("set.ops.viewrow")
                        .size(w, 38.0f)
                        .alignItems(core::Align::CENTER)
                        .gap(10.0f)
                        .content([&] {
                            txt(ui, "set.ops.viewl", "查看服务日志", 13.5f, t.ink2);
                            spacer(ui, "set.ops.viewsp");
                            btn(ui, t, "set.ops.view", 90.0f, 30.0f,
                                st.logViewOpen ? "收起" : "查看", BtnKind::Ghost, false, [] {
                                    st.logViewOpen = !st.logViewOpen;
                                    if (st.logViewOpen)
                                        st.logViewText = readFileTail(serviceLogPath(), 64 * 1024);
                                });
                        })
                        .build();
                    if (st.logViewOpen) {
                        const float cw = w - 32.0f;
                        components::card(ui, "set.ops.logcard")
                            .theme(t.tokens)
                            .width(w)
                            .wrapContentHeight()
                            .padding(16.0f)
                            .radius(6.0f)
                            .border(1.0f, t.hair)
                            .shadow(core::Shadow{})
                            .content([&] {
                                if (st.logViewText.empty())
                                    txt(ui, "set.ops.logempty",
                                        "暂无日志：打开\"服务日志落盘\"并重启应用后开始记录。", 13.0f,
                                        t.dim, "", true, cw, 19.0f);
                                else
                                    txt(ui, "set.ops.logtext",
                                        "最近 64 KB：\n" + st.logViewText, 12.5f, t.ink2,
                                        "monospace", true, cw, 17.0f);
                            })
                            .build();
                    }
                })
                .build();
        })
        .build();
}

void compose(eui::Ui& ui, const eui::Screen& screen) {
    const AppTheme& t = appTheme();
    const float colW = std::min(640.0f, screen.width - 56.0f); // 窗口过窄时内容列自适应
    const bool inSettings = st.tab == 2; // 设置是独立页面：换标题、隐藏标签页

    // 垂直预算：内容区 = 窗口高 - 上下 padding；中间滚动区吃掉剩余空间（页脚按单行 24 预算）
    const float innerH = screen.height - 56.0f;
    const float scrollH =
        inSettings ? innerH - 24.0f - 68.0f - 24.0f - 3.0f * 12.0f // 页眉+标题+窄页脚
                   : innerH - 24.0f - 68.0f - 42.0f - 24.0f - 4.0f * 12.0f; // 加标签页

    ui.column("root")
        .size(screen.width, screen.height)
        .padding(28.0f)
        .alignItems(core::Align::CENTER)
        .content([&] {
            ui.column("col")
                .size(colW, innerH)
                .gap(12.0f)
                .content([&] {
                    // 页眉：logo + 服务状态
                    ui.row("header")
                        .size(colW, 24.0f)
                        .alignItems(core::Align::CENTER)
                        .content([&] {
                            ui.row("header.logo")
                                .size(104.0f, 24.0f)
                                .gap(0.0f)
                                .alignItems(core::Align::CENTER)
                                .content([&] {
                                    txt(ui, "header.logo.a", "one", 16.0f, t.tokens.text,
                                        "monospace");
                                    txt(ui, "header.logo.b", "time", 16.0f, t.tokens.primary,
                                        "monospace");
                                })
                                .build();
                            spacer(ui, "header.sp");
                            txt(ui, "header.status", g_headerStatus, 12.0f, t.dim, "monospace");
                            ui.row("header.gap").size(10.0f, 24.0f).build();
                            btn(ui, t, "header.set", 64.0f, 24.0f, st.tab == 2 ? "返回" : "设置",
                                st.tab == 2 ? BtnKind::Primary : BtnKind::Ghost, false, [] {
                                    if (st.tab == 2) {
                                        st.tab = st.lastTab;
                                        if (st.tab == 1) refreshVault();
                                    } else {
                                        st.lastTab = st.tab;
                                        st.tab = 2;
                                    }
                                });
                        })
                        .build();

                    // 标题 + 导语；设置页换成自己的标题，主页面文案不带入
                    ui.column("title")
                        .size(colW, 68.0f)
                        .gap(6.0f)
                        .content([&] {
                            if (inSettings) {
                                txt(ui, "title.h1", "设置", 28.0f, t.tokens.text);
                                txt(ui, "title.lede",
                                    "服务、行为、外观与运维选项；标注\"重启生效\"的项保存后下次启动时"
                                    "应用，其余即时生效。",
                                    15.0f, t.ink2);
                            } else {
                                txt(ui, "title.h1", "把密钥安全递出去一次", 28.0f, t.tokens.text);
                                txt(ui, "title.lede",
                                    "两种用法：生成只可取用一次的链接递给对方；或直接存入本机金库，密钥"
                                    "全程不经过对话。",
                                    15.0f, t.ink2);
                            }
                        })
                        .build();

                    // 标签页只在主页面出现；设置页经页眉按钮进出，不再借用标签位
                    if (!inSettings)
                        segmented(ui, t, "tabs", {"一次性链接", "本机金库"}, st.tab, 14.5f, 260.0f,
                                  42.0f, [](int i) {
                                      st.tab = i;
                                      if (i == 1) refreshVault(); // 进页即刷新，清单不陈旧
                                  });

                    // 滚动内容区：当前页 + 会话记录（设置页独占——模板面板按 tab 选目标，
                    // tab 2 会误落金库模板分支，两块都加守卫）
                    components::scrollView(ui, "page.scroll")
                        .theme(t.tokens)
                        .size(colW, scrollH)
                        .content([&](eui::Ui& contentUi, float contentWidth, float) {
                            contentUi.column("page.col")
                                .width(contentWidth)
                                .height(eui::SizeValue::wrapContent())
                                .gap(20.0f)
                                .content([&] {
                                    if (st.tab == 0) composeLinkPage(contentUi, t, contentWidth);
                                    else if (st.tab == 1) composeVaultPage(contentUi, t, contentWidth);
                                    else composeSettingsPage(contentUi, t, contentWidth);
                                    if (st.tab != 2) {
                                        composeTplPanel(contentUi, t, contentWidth);
                                        if (st.settings.showRecords)
                                            composeRecords(contentUi, t, contentWidth);
                                    }
                                })
                                .build();
                        })
                        .build();

                    // 页脚：单行窄条；项目地址主色 + 手型 + 可点击
                    ui.column("footer")
                        .size(colW, 24.0f)
                        .gap(6.0f)
                        .content([&] {
                            hairline(ui, "footer.line", colW, t.hairSoft);
                            ui.row("footer.row")
                                .size(colW, 18.0f)
                                .alignItems(core::Align::CENTER)
                                .content([&] {
                                    txt(ui, "footer.label", "onetime  项目地址：", 12.5f, t.dim);
                                    // 地址文字上叠一层透明命中区，mouseArea 默认即手型光标
                                    ui.stack("footer.link")
                                        .size(336.0f, 18.0f)
                                        .content([&] {
                                            txt(ui, "footer.url", g_projectUrl, 12.5f,
                                                t.tokens.primary, "monospace");
                                            components::mouseArea(ui, "footer.hit")
                                                .size(336.0f, 18.0f)
                                                .onTap([] { openInBrowser(g_projectUrl); })
                                                .build();
                                        })
                                        .build();
                                })
                                .build();
                        })
                        .build();
                })
                .build();
        })
        .build();

    // 时效反馈的到期回退：EUI-NEO 按需重绘，无输入事件界面不会重组；框架 timer
    // 挂起期间持续驱动帧循环，到点清状态并请求重组，文案/武装态得以准时复原
    // （toast 的 3 秒自动消失即同款机制）。isArmed 等仍保留时限兜底，不单靠 timer。
    if (!st.copyDoneId.empty())
        ui.stack("timer.copy")
            .size(0.0f, 0.0f)
            .onTimer(1.6f, [] { st.copyDoneId.clear(); })
            .build();
    if (!st.armedDelete.empty())
        ui.stack("timer.arm")
            .size(0.0f, 0.0f)
            .onTimer(3.0f, [] { st.armedDelete.clear(); })
            .build();
    if (!st.tplNote.empty() || !st.setNote.empty())
        ui.stack("timer.tpl")
            .size(0.0f, 0.0f)
            .onTimer(2.4f, [] {
                st.tplNote.clear();
                st.setNote.clear();
            })
            .build();

    components::toast(ui, "toast")
        .visible(st.toastVisible)
        .screen(screen.width, screen.height)
        .theme(t.tokens)
        .title(st.toastTitle)
        .message(st.toastMsg)
        .duration(3.0f)
        .onAutoDismiss([] { st.toastVisible = false; })
        .build();
}

} // namespace app
