#pragma once

// 设置持久化：~/.onetime/settings.txt（key=value 纯文本，UTF-8，与 agent-template 同目录）
// 解析/序列化为纯函数（可单测）；IO 走 fs::u8path + 原子替换（平台差异见 platform.h）。

#include "platform.h"

#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

namespace fs = std::filesystem;

namespace onetime {

// 命令行显式键位标记：仅当值被接受时置位，settings 不得覆盖显式命令行值
enum : uint32_t {
    kCliAddr = 1,
    kCliBase = 2,
    kCliVault = 4,
};

struct Settings {
    int defaultTtlIdx = 1;      // 0..4 → 30m/1h/8h/24h/7d；仅 UI 预选，服务端默认仍由 -ttl 控制
    std::string publicBase;     // 空 = 按请求 Host 推导
    std::string listenAddr;     // 空 = 127.0.0.1:8787
    std::string vaultDir;       // 空 = ~/.onetime/secrets
    bool autoCopyLink = false;
    bool clearNameAfterPut = true;
    bool showRecords = true;
    bool darkTheme = false;
    float uiScale = 1.25f;      // 1.0 / 1.25 / 1.5
    bool autostart = false;
    bool minimizeToTray = false;
    bool logToFile = false;
};

inline int ttlIdxFromLabel(const std::string& s) {
    if (s == "30m") return 0;
    if (s == "1h") return 1;
    if (s == "8h") return 2;
    if (s == "24h") return 3;
    if (s == "7d") return 4;
    return -1;
}

inline const char* ttlLabelFromIdx(int i) {
    static const char* labels[] = {"30m", "1h", "8h", "24h", "7d"};
    return (i >= 0 && i <= 4) ? labels[i] : "1h";
}

// host:port 宽松校验：host 非空、port 为 1-65535 数字（IPv6 [::1]:8787 不支持，与 CLI 现状一致）
inline bool validHostPort(const std::string& s) {
    auto colon = s.rfind(':');
    if (colon == std::string::npos || colon == 0 || colon + 1 == s.size()) return false;
    for (size_t i = 0; i < colon; ++i)
        if ((unsigned char)s[i] < 0x20 || s[i] == ' ') return false;
    long port = 0;
    bool any = false;
    for (size_t i = colon + 1; i < s.size(); ++i) {
        if (!std::isdigit((unsigned char)s[i])) return false;
        any = true;
        port = port * 10 + (s[i] - '0');
        if (port > 65535) return false;
    }
    return any && port >= 1;
}

inline std::string stripTrailingSlash(std::string s) {
    while (!s.empty() && (s.back() == '/' || s.back() == '\\')) s.pop_back();
    return s;
}

inline Settings parseSettings(const std::string& text) {
    Settings s;
    std::istringstream in(text);
    std::string line;
    bool first = true;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (first) { // 记事本场景的 UTF-8 BOM 容错
            if (line.size() >= 3 && (unsigned char)line[0] == 0xEF &&
                (unsigned char)line[1] == 0xBB && (unsigned char)line[2] == 0xBF)
                line = line.substr(3);
            first = false;
        }
        if (line.empty() || line[0] == '#') continue;
        auto eq = line.find('='); // 按第一个 = 切分，值可再含 =
        if (eq == std::string::npos) continue;
        std::string k = line.substr(0, eq), v = line.substr(eq + 1);
        if (k == "default_ttl") {
            int i = ttlIdxFromLabel(v);
            if (i >= 0) s.defaultTtlIdx = i;
        } else if (k == "public_base") {
            s.publicBase = stripTrailingSlash(v); // 服务端 base + "/s/" 直拼，防双斜杠
        } else if (k == "listen_addr") {
            if (validHostPort(v)) s.listenAddr = v;
        } else if (k == "vault_dir") {
            s.vaultDir = v;
        } else if (k == "auto_copy_link") {
            s.autoCopyLink = v == "1";
        } else if (k == "clear_name_after_put") {
            s.clearNameAfterPut = v == "1";
        } else if (k == "show_records") {
            s.showRecords = v == "1";
        } else if (k == "theme") {
            s.darkTheme = v == "dark";
        } else if (k == "ui_scale") {
            float f = (float)atof(v.c_str());
            if (f == 1.0f || f == 1.25f || f == 1.5f) s.uiScale = f;
        } else if (k == "autostart") {
            s.autostart = v == "1";
        } else if (k == "minimize_to_tray") {
            s.minimizeToTray = v == "1";
        } else if (k == "log_to_file") {
            s.logToFile = v == "1";
        }
    }
    return s;
}

inline std::string serializeSettings(const Settings& s) {
    std::ostringstream o;
    o << "# onetime settings (key=value)\n";
    o << "default_ttl=" << ttlLabelFromIdx(s.defaultTtlIdx) << "\n";
    o << "public_base=" << s.publicBase << "\n";
    o << "listen_addr=" << s.listenAddr << "\n";
    o << "vault_dir=" << s.vaultDir << "\n";
    o << "auto_copy_link=" << (s.autoCopyLink ? 1 : 0) << "\n";
    o << "clear_name_after_put=" << (s.clearNameAfterPut ? 1 : 0) << "\n";
    o << "show_records=" << (s.showRecords ? 1 : 0) << "\n";
    o << "theme=" << (s.darkTheme ? "dark" : "light") << "\n";
    o << "ui_scale=" << s.uiScale << "\n";
    o << "autostart=" << (s.autostart ? 1 : 0) << "\n";
    o << "minimize_to_tray=" << (s.minimizeToTray ? 1 : 0) << "\n";
    o << "log_to_file=" << (s.logToFile ? 1 : 0) << "\n";
    return o.str();
}

// 合并规则：settings 覆盖默认，命令行显式键最终胜出。listenAddr 同步回写（UI 的 httpCall 用它）。
inline void applySettingsToConfig(std::string& listenAddr, std::string& publicBase, std::string& vaultDir,
                                  const Settings& s, uint32_t explicitKeys) {
    if (!(explicitKeys & kCliAddr)) {
        listenAddr = s.listenAddr.empty() ? std::string("127.0.0.1:8787") : s.listenAddr;
    }
    if (!(explicitKeys & kCliBase)) publicBase = s.publicBase;
    if (!(explicitKeys & kCliVault)) vaultDir = s.vaultDir;
}

inline std::string onetimeHomeDir() {
    return plat::homeDirUtf8();
}

inline std::string settingsPath() { return onetimeHomeDir() + "/.onetime/settings.txt"; }
inline std::string serviceLogPath() { return onetimeHomeDir() + "/.onetime/service.log"; }

inline bool loadSettingsFile(const std::string& path, Settings& out) {
    std::ifstream f(fs::u8path(path), std::ios::binary);
    if (!f) return false;
    std::ostringstream ss;
    ss << f.rdbuf();
    out = parseSettings(ss.str());
    return true;
}

inline bool saveSettingsFile(const std::string& path, const Settings& s) {
    std::error_code ec;
    fs::create_directories(fs::u8path(path).parent_path(), ec); // 首次运行 ~/.onetime 尚不存在
    std::string tmp = path + ".tmp";
    {
        std::ofstream f(fs::u8path(tmp), std::ios::binary | std::ios::trunc);
        if (!f) return false;
        std::string data = serializeSettings(s);
        f.write(data.data(), (std::streamsize)data.size());
        if (!f) return false;
    }
    if (plat::moveReplace(tmp, path, true)) return true;
    plat::removeFile(tmp);
    return false;
}

// 读文件尾部 cap 字节（服务线程追加不阻塞读取；MSVC ifstream 默认共享读）。文件缺失返回空。
inline std::string readFileTail(const std::string& path, size_t cap) {
    std::ifstream f(fs::u8path(path), std::ios::binary | std::ios::ate);
    if (!f) return {};
    auto end = f.tellg();
    if (end <= 0) return {};
    size_t size = (size_t)end;
    size_t start = size > cap ? size - cap : 0;
    f.seekg((std::streamoff)start);
    std::string out(size - start, '\0');
    f.read(out.data(), (std::streamsize)out.size());
    return out;
}

} // namespace onetime
