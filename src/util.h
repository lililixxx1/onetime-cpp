// util.h — 基础工具：base64url、恒时比较、时长解析、字符串修剪
//
//   b64Url*      base64url（无填充，URL 安全字母表）
//   constTimeEq  恒时字节比较
//   parseDur     时长语法 [数字][单位]…（30s ~ 168h 边界在调用方校验）
//   validName    `^[A-Za-z][A-Za-z0-9_]{0,63}$`（金库条目名 = 文件名）
#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace onetime {

using Clock = std::chrono::system_clock;

// ---- base64url（无填充） ----
std::string b64UrlEncode(const uint8_t* data, size_t len);

// 解码失败（非法字符或长度错）返回 false，out 不动。
bool b64UrlDecode(std::string_view in, std::string& out);

// 恒时比较：长度由调用方保证相等，避免时序侧信道。
bool constTimeEq(const uint8_t* a, const uint8_t* b, size_t n);

// ASCII 空白修剪（空格/制表/换行）。
std::string_view trimSpace(std::string_view s);

// 时长解析：可选正负号 + 一段以上 [数字][单位]，
// 单位 ns/us/µs/ms/s/m/h；解析失败或溢出返回 -1（负值同样原样返回，由调用方判范围）。
int64_t parseDur(std::string_view s);

// 时长格式化（h/m/s 组合），仅用于日志展示。
std::string formatDur(int64_t ns);

// 金库条目名规则：字母开头，仅字母/数字/下划线，至多 64 字符。
// 名字同时是文件名，正则天然排除路径分隔符与点。
bool validName(std::string_view s);

// 字符串是否含 \r 或 \n（金库值必须单行）。
bool hasNewline(std::string_view s);

} // namespace onetime
