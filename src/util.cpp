// util.cpp — 基础工具实现
#include "util.h"

#include <cctype>
#include <cstdio>

namespace onetime {

static const char kB64Url[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

std::string b64UrlEncode(const uint8_t* data, size_t len) {
    std::string out;
    out.reserve((len * 4 + 2) / 3);
    size_t i = 0;
    while (i + 3 <= len) {
        uint32_t v = (uint32_t)data[i] << 16 | (uint32_t)data[i + 1] << 8 | data[i + 2];
        out.push_back(kB64Url[(v >> 18) & 63]);
        out.push_back(kB64Url[(v >> 12) & 63]);
        out.push_back(kB64Url[(v >> 6) & 63]);
        out.push_back(kB64Url[v & 63]);
        i += 3;
    }
    if (len - i == 1) {
        uint32_t v = (uint32_t)data[i] << 16;
        out.push_back(kB64Url[(v >> 18) & 63]);
        out.push_back(kB64Url[(v >> 12) & 63]);
    } else if (len - i == 2) {
        uint32_t v = (uint32_t)data[i] << 16 | (uint32_t)data[i + 1] << 8;
        out.push_back(kB64Url[(v >> 18) & 63]);
        out.push_back(kB64Url[(v >> 12) & 63]);
        out.push_back(kB64Url[(v >> 6) & 63]);
    }
    return out;
}

static int b64Val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

bool b64UrlDecode(std::string_view in, std::string& out) {
    const size_t n = in.size();
    if (n % 4 == 1) return false; // 无填充 base64 长度模 4 不可能为 1
    std::string buf;
    buf.reserve(n / 4 * 3 + 3);
    uint32_t acc = 0;
    int bits = 0;
    for (char c : in) {
        int v = b64Val(c);
        if (v < 0) return false;
        acc = acc << 6 | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            buf.push_back((char)((acc >> bits) & 0xff));
        }
    }
    out.swap(buf);
    return true;
}

bool constTimeEq(const uint8_t* a, const uint8_t* b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

std::string_view trimSpace(std::string_view s) {
    size_t b = 0, e = s.size();
    auto isSpace = [](char c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v';
    };
    while (b < e && isSpace(s[b])) ++b;
    while (e > b && isSpace(s[e - 1])) --e;
    return s.substr(b, e - b);
}

int64_t parseDur(std::string_view s) {
    if (s.empty()) return -1;
    size_t i = 0;
    bool neg = false;
    if (s[0] == '+' || s[0] == '-') {
        neg = s[0] == '-';
        i = 1;
        if (i == s.size()) return -1;
    }
    if (s == "0") return 0;
    int64_t total = 0;
    bool any = false;
    while (i < s.size()) {
        if (!std::isdigit((unsigned char)s[i])) return -1;
        int64_t num = 0;
        size_t digits = 0;
        while (i < s.size() && std::isdigit((unsigned char)s[i])) {
            num = num * 10 + (s[i] - '0');
            if (num > (int64_t)1 << 50) return -1; // 防溢出，足够 168h 级别
            ++i;
            ++digits;
        }
        if (digits == 0 || i == s.size()) return -1;
        int64_t unitNs = -1;
        char u0 = s[i];
        if (u0 == 'n' && s.substr(i, 2) == "ns") { unitNs = 1; i += 2; }
        else if (u0 == 'u' && s.substr(i, 2) == "us") { unitNs = 1000; i += 2; }
        else if (u0 == static_cast<char>(0xc2) && i + 1 < s.size() &&
                 s[i + 1] == static_cast<char>(0xb5) && s.substr(i + 2, 1) == "s") {
            unitNs = 1000; i += 3; // µs（U+00B5）
        }
        else if (u0 == 'm' && s.substr(i, 2) == "ms") { unitNs = 1000000; i += 2; }
        else if (u0 == 's') { unitNs = 1000000000; i += 1; }
        else if (u0 == 'm') { unitNs = 60ll * 1000000000; i += 1; }
        else if (u0 == 'h') { unitNs = 3600ll * 1000000000; i += 1; }
        else return -1;
        total += num * unitNs;
        if (total > (int64_t)1 << 53) return -1;
        any = true;
    }
    if (!any) return -1;
    return neg ? -total : total;
}

std::string formatDur(int64_t ns) {
    if (ns < 0) ns = 0;
    int64_t s = ns / 1000000000;
    int64_t h = s / 3600, m = (s % 3600) / 60, sec = s % 60;
    char buf[64];
    if (h > 0) std::snprintf(buf, sizeof buf, "%lldh%lldm%llds", (long long)h, (long long)m, (long long)sec);
    else if (m > 0) std::snprintf(buf, sizeof buf, "%lldm%llds", (long long)m, (long long)sec);
    else std::snprintf(buf, sizeof buf, "%llds", (long long)sec);
    return buf;
}

bool validName(std::string_view s) {
    if (s.empty() || s.size() > 64) return false;
    char c0 = s[0];
    if (!(c0 >= 'A' && c0 <= 'Z') && !(c0 >= 'a' && c0 <= 'z')) return false;
    for (char c : s) {
        bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c == '_';
        if (!ok) return false;
    }
    return true;
}

bool hasNewline(std::string_view s) {
    for (char c : s)
        if (c == '\r' || c == '\n') return true;
    return false;
}

} // namespace onetime
