// httplite.h — 极简阻塞 HTTP/1.1 客户端（GUI 与单测共用）
//
// GUI 窗口和 curl/agent 一样，只是本机服务端的普通客户端——
// 所有校验、守卫、加密逻辑只在服务端存在一份。
// 阻塞式调用，只应在工作线程（app::async 的 work 或测试线程）中使用。
#pragma once

#include "platform.h"

#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>

namespace onetime {

struct HttpResult {
    int status = 0;                              // 0 = 连接/传输失败
    std::map<std::string, std::string> headers;  // 键已小写
    std::string body;
    std::string err;
};

// addr 形如 "127.0.0.1:8787" 或 "localhost:8787"。
inline HttpResult httpCall(const std::string& addr, const std::string& method,
                           const std::string& pathQuery, const std::string& body,
                           const std::vector<std::pair<std::string, std::string>>& extraHeaders = {},
                           int timeoutMs = 10000) {
    HttpResult res;
    auto colon = addr.rfind(':');
    if (colon == std::string::npos) {
        res.err = "bad address";
        return res;
    }
    std::string host = addr.substr(0, colon), port = addr.substr(colon + 1);
    if (!host.empty() && host.front() == '[' && host.back() == ']') host = host.substr(1, host.size() - 2);

    plat::AddrInfoList ais;
    if (!ais.resolve(host, port, false)) {
        res.err = "resolve failed";
        return res;
    }
    plat::SockHandle s = plat::kInvalidSock;
    for (size_t i = 0;; ++i) {
        plat::AddrInfoList::Entry ai;
        if (!ais.at(i, ai)) break;
        s = socket(ai.family, ai.socktype, ai.protocol);
        if (s == plat::kInvalidSock) continue;
        plat::sockSetTimeoutMs(s, timeoutMs);
        if (connect(s, ai.addr, ai.addrlen) == 0) break;
        plat::sockClose(s);
        s = plat::kInvalidSock;
    }
    if (s == plat::kInvalidSock) {
        res.err = "connect failed";
        return res;
    }

    bool hasHostOverride = false;
    for (auto& kv : extraHeaders) {
        std::string k = kv.first;
        for (char& ch : k)
            if (ch >= 'A' && ch <= 'Z') ch += 32;
        if (k == "host") hasHostOverride = true;
    }
    std::string req = method + " " + pathQuery + " HTTP/1.1\r\n";
    if (!hasHostOverride) req += "Host: " + addr + "\r\n"; // 测试可用 Host 覆盖测 hostGuard
    for (auto& kv : extraHeaders) req += kv.first + ": " + kv.second + "\r\n";
    if (!body.empty() || method == "POST")
        req += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    req += "Connection: close\r\n\r\n";
    req += body;

    {
        size_t off = 0;
        while (off < req.size()) {
            int n = plat::sendSock(s, req.data() + off, (int)(req.size() - off));
            if (n <= 0) {
                plat::sockClose(s);
                res.err = "send failed";
                return res;
            }
            off += (size_t)n;
        }
    }

    std::string all;
    char buf[16384];
    for (;;) {
        int n = recv(s, buf, sizeof buf, 0);
        if (n <= 0) break;
        all.append(buf, (size_t)n);
    }
    plat::sockClose(s);

    auto headEnd = all.find("\r\n\r\n");
    if (headEnd == std::string::npos) {
        res.err = "truncated response";
        return res;
    }
    size_t lineEnd = all.find("\r\n");
    int code = atoi(all.c_str() + 9); // "HTTP/1.1 NNN"
    res.status = code;
    size_t pos = lineEnd + 2;
    while (pos < headEnd) {
        size_t eol = all.find("\r\n", pos);
        if (eol == std::string::npos || eol == pos) break;
        std::string line = all.substr(pos, eol - pos);
        auto c = line.find(':');
        if (c != std::string::npos) {
            std::string key = line.substr(0, c);
            for (char& ch : key)
                if (ch >= 'A' && ch <= 'Z') ch += 32;
            size_t vb = c + 1;
            while (vb < line.size() && line[vb] == ' ') ++vb;
            res.headers[key] = line.substr(vb);
        }
        pos = eol + 2;
    }
    // 读到关闭即全文；去掉按 Content-Length 的多读（服务器总是 close，直接取余量）
    res.body = all.substr(headEnd + 4);
    return res;
}

} // namespace onetime
