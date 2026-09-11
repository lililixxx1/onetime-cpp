// crypto_posix.cpp — Linux 自带实现（Windows 对应 crypto_win.cpp）。
//
// 接口语义与 CNG 分支逐字节一致：密文 || 16 字节 tag；AAD 恒空；nonce 12 字节；
// 解密先恒时比较 tag 再输出明文（认证失败即整体失败）。
//
// 正确性由测试锁定（tests/test_main.cpp）：NIST GCM 官方向量 + Windows CNG
// 硬编码期望值交叉验证——本实现必须逐字节复现两组向量。
//
// 时序取舍（有意为之）：S-box 直查实现非抗缓存侧信道的常时设计，GHASH 移位
// 乘法同理。威胁模型：服务只绑 127.0.0.1（回环），无远程可达的时序攻击面；
// 密钥只存在于一次性链接，不在服务端驻留。朴素实现的吞吐（~10 MB/s 级）对
// 单条 ≤1 MiB 的一次性密钥场景足够。
#include "crypto.h"

#include "util.h" // constTimeEq

#include <cstdint>
#include <cstring>

#if defined(__linux__) && __has_include(<sys/random.h>)
#include <sys/random.h>
#define ONETIME_HAVE_GETRANDOM 1
#endif
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>

namespace onetime {

bool secureRandom(uint8_t* buf, size_t len) {
#if ONETIME_HAVE_GETRANDOM
    {
        size_t got = 0;
        bool unsupported = false;
        while (got < len) {
            ssize_t n = getrandom(buf + got, len - got, 0);
            if (n < 0) {
                if (errno == ENOSYS) { unsupported = true; break; } // 老内核转 urandom
                if (errno == EINTR) continue;
                return false;
            }
            got += (size_t)n;
        }
        if (!unsupported && got == len) return true;
    }
#endif
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, buf + got, len - got);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return false;
        }
        if (n == 0) break; // 不应发生；按失败处理
        got += (size_t)n;
    }
    close(fd);
    return got == len;
}

// ---------------- SHA-256（FIPS 180-4，一次性摘要） ----------------

namespace {

const uint32_t kSha256K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2};

inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

void sha256Compress(uint32_t h[8], const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i)
        w[i] = (uint32_t)block[i * 4] << 24 | (uint32_t)block[i * 4 + 1] << 16 |
               (uint32_t)block[i * 4 + 2] << 8 | (uint32_t)block[i * 4 + 3];
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = hh + S1 + ch + kSha256K[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

// ---------------- AES-256 加密方向（FIPS 197；GCM 加解密共用） ----------------

const uint8_t kSbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
    0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
    0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
    0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
    0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
    0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
    0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
    0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
    0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
    0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
    0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
    0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
    0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
    0x16};

inline uint8_t xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0)); }

struct Aes256 {
    uint32_t rk[60]; // 轮密钥字（Nb*(Nr+1) = 60，大端字）

    explicit Aes256(const uint8_t key[32]) {
        for (int i = 0; i < 8; ++i)
            rk[i] = (uint32_t)key[i * 4] << 24 | (uint32_t)key[i * 4 + 1] << 16 |
                    (uint32_t)key[i * 4 + 2] << 8 | (uint32_t)key[i * 4 + 3];
        static const uint32_t rcon[8] = {0, 0x01000000, 0x02000000, 0x04000000,
                                         0x08000000, 0x10000000, 0x20000000, 0x40000000};
        for (int i = 8; i < 60; ++i) {
            uint32_t t = rk[i - 1];
            if (i % 8 == 0)
                t = (kSbox[(t >> 16) & 0xff] << 24) | (kSbox[(t >> 8) & 0xff] << 16) |
                    (kSbox[t & 0xff] << 8) | kSbox[t >> 24]; // SubWord(RotWord(t))
            else if (i % 8 == 4)
                t = (kSbox[t >> 24] << 24) | (kSbox[(t >> 16) & 0xff] << 16) |
                    (kSbox[(t >> 8) & 0xff] << 8) | kSbox[t & 0xff]; // SubWord(t)
            rk[i] = rk[i - 8] ^ (i % 8 == 0 ? t ^ rcon[i / 8] : t);
        }
    }

    void encryptBlock(uint8_t block[16]) const {
        uint8_t s[16];
        memcpy(s, block, 16);
        addRoundKey(s, 0);
        for (int round = 1; round <= 13; ++round) {
            subBytes(s);
            shiftRows(s);
            mixColumns(s);
            addRoundKey(s, round);
        }
        subBytes(s);
        shiftRows(s);
        addRoundKey(s, 14);
        memcpy(block, s, 16);
    }

private:
    void addRoundKey(uint8_t s[16], int round) const {
        for (int c = 0; c < 4; ++c) {
            uint32_t w = rk[round * 4 + c];
            s[c * 4] ^= (uint8_t)(w >> 24);
            s[c * 4 + 1] ^= (uint8_t)(w >> 16);
            s[c * 4 + 2] ^= (uint8_t)(w >> 8);
            s[c * 4 + 3] ^= (uint8_t)w;
        }
    }
    static void subBytes(uint8_t s[16]) {
        for (int i = 0; i < 16; ++i) s[i] = kSbox[s[i]];
    }
    static void shiftRows(uint8_t s[16]) {
        uint8_t t;
        // 行 1 左移 1：列主序 state[r + 4c]
        t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
        // 行 2 左移 2
        t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
        // 行 3 左移 3（=右移 1）
        t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
    }
    static void mixColumns(uint8_t s[16]) {
        for (int c = 0; c < 4; ++c) {
            uint8_t* p = s + c * 4;
            uint8_t a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
            p[0] = (uint8_t)(xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3);
            p[1] = (uint8_t)(a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3);
            p[2] = (uint8_t)(a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3);
            p[3] = (uint8_t)(xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3));
        }
    }
};

// ---------------- GCM（NIST SP 800-38D，96-bit nonce，无 AAD） ----------------

// GF(2^128) 乘法（SP 800-38D Algorithm 1，z = x·y）。块内大端，u[0]=高 64 位。
void gfMul(const uint64_t x[2], const uint64_t y[2], uint64_t z[2]) {
    z[0] = z[1] = 0;
    uint64_t vh = y[0], vl = y[1];
    for (int i = 0; i < 128; ++i) {
        // x 的第 i 位（x_0 为最高位）
        uint64_t bit = (i < 64) ? ((x[0] >> (63 - i)) & 1) : ((x[1] >> (127 - i)) & 1);
        if (bit) {
            z[0] ^= vh;
            z[1] ^= vl;
        }
        bool lsb = (vl & 1) != 0;
        vl = (vl >> 1) | (vh << 63);
        vh >>= 1;
        if (lsb) vh ^= 0xe1ULL << 56; // R = 11100001 || 0^120
    }
}

inline uint64_t loadBe64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}

inline void storeBe64(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (56 - 8 * i));
}

// GCM 单次 seal（业务层仅此一处使用；AAD 恒空是接口语义）。
// out = CTR(inc32(J0), in)；tag 输出到 tagOut。
// ghashSrc：认证的数据源——加密传密文（CTR 循环写完后的 out），解密传密文 ct
// （此时 out 是解出的明文，GHASH 必须始终对密文计算）。
void gcmSeal(const uint8_t key[32], const uint8_t nonce[12], const uint8_t* in, size_t len,
             uint8_t* out, uint8_t tagOut[16], const uint8_t* ghashSrc) {
    Aes256 aes(key);
    uint8_t hBlock[16] = {0}; // H = E(K, 0^128)
    aes.encryptBlock(hBlock);
    const uint64_t H[2] = {loadBe64(hBlock), loadBe64(hBlock + 8)};

    uint8_t j0[16]; // J0 = IV || 0^31 || 1
    memcpy(j0, nonce, 12);
    j0[12] = j0[13] = j0[14] = 0;
    j0[15] = 1;

    // CTR 流（从 inc32(J0) 起）
    uint8_t cb[16];
    memcpy(cb, j0, 16);
    for (size_t off = 0; off < len; off += 16) {
        // inc32（大端低 32 位 +1）
        uint32_t c = (uint32_t)cb[12] << 24 | (uint32_t)cb[13] << 16 | (uint32_t)cb[14] << 8 |
                     cb[15];
        c++;
        cb[12] = (uint8_t)(c >> 24);
        cb[13] = (uint8_t)(c >> 16);
        cb[14] = (uint8_t)(c >> 8);
        cb[15] = (uint8_t)c;
        uint8_t ks[16];
        memcpy(ks, cb, 16);
        aes.encryptBlock(ks);
        size_t n = len - off < 16 ? len - off : 16;
        for (size_t i = 0; i < n; ++i) out[off + i] = in[off + i] ^ ks[i];
    }

    // GHASH：CT 块 ‖ len 块（AAD 恒空，长度单位为比特）
    uint64_t acc[2] = {0, 0};
    uint64_t prod[2];
    for (size_t off = 0; off < len; off += 16) {
        size_t n = len - off < 16 ? len - off : 16;
        uint8_t blk[16] = {0};
        memcpy(blk, ghashSrc + off, n);
        uint64_t X[2] = {acc[0] ^ loadBe64(blk), acc[1] ^ loadBe64(blk + 8)};
        gfMul(X, H, prod);
        acc[0] = prod[0];
        acc[1] = prod[1];
    }
    uint8_t lenBlk[16];
    storeBe64(lenBlk, 0); // AAD 比特长度
    storeBe64(lenBlk + 8, (uint64_t)len * 8);
    uint64_t X[2] = {acc[0] ^ loadBe64(lenBlk), acc[1] ^ loadBe64(lenBlk + 8)};
    gfMul(X, H, prod);

    // T = E(K, J0) ⊕ GHASH
    uint8_t ej0[16];
    memcpy(ej0, j0, 16);
    aes.encryptBlock(ej0);
    uint64_t g[2] = {prod[0], prod[1]};
    for (int i = 0; i < 8; ++i) tagOut[i] = (uint8_t)(g[0] >> (56 - 8 * i));
    for (int i = 0; i < 8; ++i) tagOut[8 + i] = (uint8_t)(g[1] >> (56 - 8 * i));
    for (int i = 0; i < 16; ++i) tagOut[i] ^= ej0[i];
}

} // namespace

bool sha256(const uint8_t* data, size_t len, Sha256Digest& out) {
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    const uint64_t totalBits = (uint64_t)len * 8;
    while (len >= 64) {
        sha256Compress(h, data);
        data += 64;
        len -= 64;
    }
    uint8_t tail[128];
    const size_t tailTotal = len < 56 ? 64 : 128;
    memset(tail, 0, sizeof tail);
    memcpy(tail, data, len);
    tail[len] = 0x80;
    for (int i = 0; i < 8; ++i) tail[tailTotal - 1 - i] = (uint8_t)(totalBits >> (8 * i));
    sha256Compress(h, tail);
    if (tailTotal == 128) sha256Compress(h, tail + 64);
    for (int i = 0; i < 8; ++i) {
        out[i * 4] = (uint8_t)(h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)h[i];
    }
    return true;
}

bool aesGcmEncrypt(const uint8_t key[32], const uint8_t nonce[12],
                   const uint8_t* pt, size_t ptLen, std::string& ctOut) {
    std::string buf;
    buf.resize(ptLen + 16);
    uint8_t* out = (uint8_t*)buf.data();
    if (ptLen > 0) gcmSeal(key, nonce, pt, ptLen, out, out + ptLen, out);
    else gcmSeal(key, nonce, pt, 0, nullptr, out, nullptr);
    ctOut.swap(buf);
    return true;
}

bool aesGcmDecrypt(const uint8_t key[32], const uint8_t nonce[12],
                   const uint8_t* ct, size_t ctLen, std::string& ptOut) {
    if (ctLen < 16) return false;
    const size_t ptLen = ctLen - 16;
    std::string buf;
    buf.resize(ptLen + 16);
    uint8_t tag[16];
    gcmSeal(key, nonce, ct, ptLen, (uint8_t*)buf.data(), tag, ct); // GHASH 对密文
    if (!constTimeEq(tag, ct + ptLen, 16)) return false; // 认证失败：不输出任何明文
    buf.resize(ptLen);
    ptOut.swap(buf);
    return true;
}

} // namespace onetime
