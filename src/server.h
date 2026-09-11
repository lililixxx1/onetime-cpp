// server.h — onetime C++ 版服务端：一次性密钥链接 + 本机金库
//
// 纯服务端实现，无任何第三方依赖：
// 原生套接字 HTTP/1.1 + AES-256-GCM 加密（Windows CNG / POSIX 自带实现）+ std::filesystem 金库。
// 前端（EUI-NEO 窗口）与 curl/agent 一样只是本服务的客户端。
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace onetime {

struct ServerConfig {
    std::string listenAddr = "127.0.0.1:8787"; // 监听地址（保持 127.0.0.1 即不暴露网络）
    std::string publicBase;                    // 生成链接基地址；空 = http://<请求 Host>
    int64_t defaultTtlNs = 3600ll * 1000000000; // 默认存活期 1h
    std::string vaultDir;                      // 空 = ~/.onetime/secrets/
    int maxEntries = 1000;                     // 声明为可变字段仅为测试缩小封顶
    int64_t maxTotalCt = 64ll << 20;           // 密文总量上限 64 MiB
    bool logToFile = false;                    // 日志落盘 ~/.onetime/service.log（启动期常量）
};

// 阻塞运行（监听 + 串行处理循环）。监听失败返回 false；正常情况不返回。
// chosenAddrOut 非空时，listen 成功即回写实际监听地址（支持端口 0 临时分配，
// 写入发生在进入 accept 循环之前，GUI/测试拿到即可连）。
bool runServer(const ServerConfig& cfg, std::string* chosenAddrOut);

// 默认金库目录 ~/.onetime/secrets（UTF-8，取自 USERPROFILE）。
std::string defaultVaultDir();

// hostGuard 纯函数（供单测）：Host 头是否放行。
// 放行：localhost、任意 IP 字面量（v4/v6）、监听地址本身；其余域名一律拒绝。
bool hostAllowed(std::string_view hostHeader, std::string_view listenHost);

// 生成链接主机规范化（供单测）：回环 IP 一律改写为 localhost
// （浏览器/WinHTTP/较新 curl 默认不给 127.0.0.1 绕过系统代理，localhost 有此待遇；
// 链接里带着解密 key，被代理转发等于把 key 写进代理日志）。
std::string canonicalLinkHost(std::string_view hostport);

} // namespace onetime
