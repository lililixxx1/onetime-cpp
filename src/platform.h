// platform.h — 平台差异层（header-only）
//
// 业务层（server.cpp / httplite.h / settings.h / main.cpp / tests）的全部 OS 专属
// 调用集中到这里：文件原子替换/删除、UTF-8 路径 fopen、单调时钟、本地时间、
// 主目录、可执行文件路径、套接字句柄/关闭/超时/send、名字解析。
// 上层只看 UTF-8 字符串与 C 标准类型，不直接引系统头。
//
// 套接字两处语义差异（历史上最容易踩的坑）：
//   1. SO_RCVTIMEO/SO_SNDTIMEO：Windows 传 DWORD 毫秒，POSIX 传 struct timeval
//      —— 统一为 sockSetTimeoutMs(fd, ms) 一处换算（内部同时设收发两个方向）。
//   2. POSIX 对已关闭连接 send 默认触发 SIGPIPE 终止进程（Windows 无此语义）
//      —— sendSock 一律带 MSG_NOSIGNAL，runServer 里另做进程级
//      signal(SIGPIPE, SIG_IGN) 兜底。
#pragma once

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <mutex>
#include <string>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctime>
#endif

namespace onetime {
namespace plat {

// ---------------- 路径：全部按 UTF-8 字节串进出 ----------------

// 原子替换/改名。allowReplace=true 时目标存在则替换（POSIX rename 原生原子；
// Windows MoveFileExW）；false 时目标存在则失败（仅金库旧版迁移使用，stat 竞态
// 窗口可接受——最坏覆盖上次中断迁移的残留）。
inline bool moveReplace(const std::string& from, const std::string& to, bool allowReplace) {
#ifdef _WIN32
    DWORD flags = allowReplace ? MOVEFILE_REPLACE_EXISTING : 0;
    return MoveFileExW(std::filesystem::u8path(from).wstring().c_str(),
                       std::filesystem::u8path(to).wstring().c_str(), flags) != FALSE;
#else
    if (!allowReplace) {
        struct stat st;
        if (::stat(to.c_str(), &st) == 0) return false;
    }
    return ::rename(from.c_str(), to.c_str()) == 0;
#endif
}

// 删除文件；目标不存在视为成功（与旧版 DeleteFileW + ERROR_FILE_NOT_FOUND 语义一致）。
inline bool removeFile(const std::string& path) {
#ifdef _WIN32
    if (DeleteFileW(std::filesystem::u8path(path).wstring().c_str())) return true;
    return GetLastError() == ERROR_FILE_NOT_FOUND;
#else
    if (::unlink(path.c_str()) == 0) return true;
    return errno == ENOENT;
#endif
}

inline bool fileExists(const std::string& path) {
#ifdef _WIN32
    return GetFileAttributesW(std::filesystem::u8path(path).wstring().c_str()) !=
           INVALID_FILE_ATTRIBUTES;
#else
    struct stat st;
    return ::stat(path.c_str(), &st) == 0;
#endif
}

inline FILE* fopenRead(const std::string& path) {
#ifdef _WIN32
    FILE* f = nullptr;
    return _wfopen_s(&f, std::filesystem::u8path(path).wstring().c_str(), L"rb") == 0 ? f
                                                                                     : nullptr;
#else
    return std::fopen(path.c_str(), "rb");
#endif
}

inline FILE* fopenWrite(const std::string& path) {
#ifdef _WIN32
    FILE* f = nullptr;
    return _wfopen_s(&f, std::filesystem::u8path(path).wstring().c_str(), L"wb") == 0 ? f
                                                                                     : nullptr;
#else
    return std::fopen(path.c_str(), "wb");
#endif
}

// ---------------- 时间 / 环境 ----------------

// 单调毫秒（连接预算、IO 超时共用）。Windows GetTickCount64 /
// POSIX CLOCK_MONOTONIC——两者都不受系统时间跳变影响。
inline uint64_t nowMs() {
#ifdef _WIN32
    return GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
#endif
}

// 线程安全本地时间（Windows localtime_s / POSIX localtime_r）。
inline void localTime(time_t t, std::tm& out) {
#ifdef _WIN32
    localtime_s(&out, &t);
#else
    localtime_r(&t, &out);
#endif
}

// stderr 是否连接到交互控制台（决定日志是否同时打到 stderr）。
inline bool stderrIsConsole() {
#ifdef _WIN32
    HANDLE err = GetStdHandle(STD_ERROR_HANDLE);
    DWORD mode = 0;
    return err && err != INVALID_HANDLE_VALUE && GetConsoleMode(err, &mode);
#else
    return isatty(fileno(stderr)) != 0;
#endif
}

// 调试通道（Windows 调试器输出；POSIX 无对应物，为空操作）。
inline void debugLogLine(const char* text) {
#ifdef _WIN32
    OutputDebugStringA(text);
#else
    (void)text;
#endif
}

// 用户主目录（UTF-8）。失败回退 "."（与旧版行为一致）。
inline std::string homeDirUtf8() {
#ifdef _WIN32
    const wchar_t* home = _wgetenv(L"USERPROFILE");
    if (!home) return ".";
    int need = WideCharToMultiByte(CP_UTF8, 0, home, -1, nullptr, 0, nullptr, nullptr);
    std::string u8((size_t)(need > 1 ? need - 1 : 0), '\0');
    if (need > 1) WideCharToMultiByte(CP_UTF8, 0, home, -1, &u8[0], need, nullptr, nullptr);
    return u8;
#else
    const char* home = std::getenv("HOME");
    return home && *home ? std::string(home) : std::string(".");
#endif
}

// 当前可执行文件绝对路径（UTF-8）；失败返回空串。
inline std::string exePathUtf8() {
#ifdef _WIN32
    wchar_t buf[MAX_PATH];
    DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return {};
    int need = WideCharToMultiByte(CP_UTF8, 0, buf, (int)n, nullptr, 0, nullptr, nullptr);
    std::string u8((size_t)(need > 0 ? need : 0), '\0');
    if (need > 0) WideCharToMultiByte(CP_UTF8, 0, buf, (int)n, &u8[0], need, nullptr, nullptr);
    return u8;
#else
    char buf[4096];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof buf - 1);
    if (n <= 0) return {};
    buf[n] = '\0';
    return std::string(buf, (size_t)n);
#endif
}

// ---------------- 套接字 ----------------

#ifdef _WIN32
using SockHandle = SOCKET;
constexpr SockHandle kInvalidSock = INVALID_SOCKET;
#define ONETIME_MSG_NOSIGNAL 0
#else
using SockHandle = int;
constexpr SockHandle kInvalidSock = -1;
#define ONETIME_MSG_NOSIGNAL MSG_NOSIGNAL
#endif

inline void sockClose(SockHandle s) {
#ifdef _WIN32
    closesocket(s);
#else
    ::close(s);
#endif
}

// 毫秒级收/发超时（内部同时设置 SO_RCVTIMEO 与 SO_SNDTIMEO）。
inline bool sockSetTimeoutMs(SockHandle s, int ms) {
#ifdef _WIN32
    DWORD v = (DWORD)ms;
    return setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&v, sizeof v) == 0 &&
           setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&v, sizeof v) == 0;
#else
    struct timeval tv;
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    return setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) == 0 &&
           setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv) == 0;
#endif
}

// send 的平台统一入口：POSIX 带 MSG_NOSIGNAL 防 SIGPIPE 终止进程。
inline int sendSock(SockHandle s, const char* buf, int len) {
    return (int)send(s, buf, len, ONETIME_MSG_NOSIGNAL);
}

// getaddrinfo 的窄字符统一封装（Windows 内部转宽字符 + 惰性 WSAStartup——
// 消除"首个 Winsock 调用必须晚于 runServer"的顺序假设）。
class AddrInfoList {
public:
    struct Entry {
        int family, socktype, protocol;
        const sockaddr* addr;
        socklen_t addrlen;
    };

    bool resolve(const std::string& host, const std::string& port, bool passive) {
        freeList();
#ifdef _WIN32
        static std::once_flag wsaOnce;
        std::call_once(wsaOnce, [] {
            WSADATA wsa;
            WSAStartup(MAKEWORD(2, 2), &wsa); // 失败留待后续 socket 调用暴露
        });
        ADDRINFOW hints = {};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        if (passive) hints.ai_flags = AI_PASSIVE;
        int wneed = MultiByteToWideChar(CP_UTF8, 0, host.c_str(), -1, nullptr, 0);
        int pneed = MultiByteToWideChar(CP_UTF8, 0, port.c_str(), -1, nullptr, 0);
        if (wneed <= 0 || pneed <= 0) return false;
        std::wstring whost((size_t)wneed, L'\0'), wport((size_t)pneed, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, host.c_str(), -1, &whost[0], wneed - 1);
        MultiByteToWideChar(CP_UTF8, 0, port.c_str(), -1, &wport[0], pneed - 1);
        ADDRINFOW* res = nullptr;
        if (GetAddrInfoW(whost.c_str(), wport.c_str(), &hints, &res) != 0 || !res) return false;
        list_ = res;
        return true;
#else
        struct addrinfo hints = {};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        if (passive) hints.ai_flags = AI_PASSIVE;
        struct addrinfo* res = nullptr;
        if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0 || !res) return false;
        list_ = res;
        return true;
#endif
    }

    // 第 idx 个候选（按 getaddrinfo 顺序）；越界返回 false。
    bool at(size_t idx, Entry& out) const {
#ifdef _WIN32
        ADDRINFOW* p = list_;
#else
        struct addrinfo* p = list_;
#endif
        for (size_t i = 0; p; p = p->ai_next, ++i) {
            if (i == idx) {
                out.family = p->ai_family;
                out.socktype = p->ai_socktype;
                out.protocol = p->ai_protocol;
                out.addr = p->ai_addr;
                out.addrlen = (socklen_t)p->ai_addrlen;
                return true;
            }
        }
        return false;
    }

    ~AddrInfoList() { freeList(); }

private:
    void freeList() {
        if (!list_) return;
#ifdef _WIN32
        FreeAddrInfoW(list_);
#else
        freeaddrinfo(list_);
#endif
        list_ = nullptr;
    }
#ifdef _WIN32
    ADDRINFOW* list_ = nullptr;
#else
    struct addrinfo* list_ = nullptr;
#endif
};

} // namespace plat
} // namespace onetime
