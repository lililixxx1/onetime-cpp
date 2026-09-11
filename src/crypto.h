// crypto.h — 密码学原语：CSPRNG / SHA-256 / AES-256-GCM
//
// 不引入任何第三方密码库：Windows 走 CNG（bcrypt），POSIX 用自带实现
// （crypto_win.cpp / crypto_posix.cpp 按平台二选一），两者输出由测试向量锁定逐字节一致。
//   secureRandom 系统熵源（BCryptGenRandom / getrandom）
//   sha256       SHA-256 一次性摘要
//   aesGcm*      AES-256-GCM，12 字节 nonce、16 字节 tag，tag 追加在密文末尾
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace onetime {

// 系统级安全随机。失败（熵源不可用）返回 false，调用方按致命错误处理。
bool secureRandom(uint8_t* buf, size_t len);

using Sha256Digest = std::array<uint8_t, 32>;
bool sha256(const uint8_t* data, size_t len, Sha256Digest& out);

// 加密：pt 明文 → ctOut = 密文 || tag（共 ptLen + 16 字节）。
bool aesGcmEncrypt(const uint8_t key[32], const uint8_t nonce[12],
                   const uint8_t* pt, size_t ptLen, std::string& ctOut);

// 解密：ct 密文（含末尾 16 字节 tag）。认证失败或入参短于 tag 返回 false。
bool aesGcmDecrypt(const uint8_t key[32], const uint8_t nonce[12],
                   const uint8_t* ct, size_t ctLen, std::string& ptOut);

} // namespace onetime
