// crypto_win.cpp — Windows CNG 实现（Linux 对应 crypto_posix.cpp）。算法句柄
// 进程内共享（CNG 算法句柄线程安全，打开后只读），密钥/哈希对象按次创建，
// 避免跨请求复用密钥材料。两平台输出布局一致：密文 || 16 字节 tag。
#include "crypto.h"

#include <atomic>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

namespace onetime {

bool secureRandom(uint8_t* buf, size_t len) {
    NTSTATUS st = BCryptGenRandom(nullptr, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return BCRYPT_SUCCESS(st);
}

// ---- 进程级算法句柄：只缓存成功结果，失败当次返回 nullptr、下次调用重试 ----
// （与"每次重开"的逐次语义等价，不会把一次瞬时失败锁存成永久故障）。
// 并发首开用 CAS 收敛，输家关闭自己的句柄；CNG 算法句柄打开后可多线程
// 并发用于 CreateHash / GenerateSymmetricKey。

static BCRYPT_ALG_HANDLE sha256Alg() {
    static std::atomic<BCRYPT_ALG_HANDLE> cached{nullptr};
    BCRYPT_ALG_HANDLE h = cached.load(std::memory_order_acquire);
    if (h) return h;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&h, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
        return nullptr;
    BCRYPT_ALG_HANDLE expected = nullptr;
    if (cached.compare_exchange_strong(expected, h, std::memory_order_release)) return h;
    BCryptCloseAlgorithmProvider(h, 0);
    return expected; // 竞争输家的 CAS 失败后 expected 即赢家句柄
}

static BCRYPT_ALG_HANDLE aesGcmAlg() {
    static std::atomic<BCRYPT_ALG_HANDLE> cached{nullptr};
    BCRYPT_ALG_HANDLE h = cached.load(std::memory_order_acquire);
    if (h) return h;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&h, BCRYPT_AES_ALGORITHM, nullptr, 0)))
        return nullptr;
    // 打开句柄后切到 GCM 链模式（该属性必须设在算法句柄上；共享句柄只设一次）
    NTSTATUS st = BCryptSetProperty(h, BCRYPT_CHAINING_MODE,
                                    (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                                    sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(st)) {
        BCryptCloseAlgorithmProvider(h, 0);
        return nullptr;
    }
    BCRYPT_ALG_HANDLE expected = nullptr;
    if (cached.compare_exchange_strong(expected, h, std::memory_order_release)) return h;
    BCryptCloseAlgorithmProvider(h, 0);
    return expected;
}

bool sha256(const uint8_t* data, size_t len, Sha256Digest& out) {
    BCRYPT_ALG_HANDLE alg = sha256Alg();
    if (!alg) return false;

    BCRYPT_HASH_HANDLE hash = nullptr;
    NTSTATUS st = BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0);
    if (!BCRYPT_SUCCESS(st)) return false;
    bool ok = false;
    st = BCryptHashData(hash, (PUCHAR)data, (ULONG)len, 0);
    if (BCRYPT_SUCCESS(st)) {
        st = BCryptFinishHash(hash, out.data(), (ULONG)out.size(), 0);
        ok = BCRYPT_SUCCESS(st);
    }
    BCryptDestroyHash(hash);
    return ok;
}

// gcmCtx：共享 AES-GCM 算法句柄（不拥有）+ 按次生成的密钥对象。
struct GcmCtx {
    BCRYPT_KEY_HANDLE key = nullptr;
    bool open(const uint8_t keyBytes[32]) {
        BCRYPT_ALG_HANDLE alg = aesGcmAlg();
        if (!alg) return false;
        NTSTATUS st = BCryptGenerateSymmetricKey(alg, &key, nullptr, 0,
                                                 (PUCHAR)keyBytes, 32, 0);
        return BCRYPT_SUCCESS(st);
    }
    ~GcmCtx() {
        if (key) BCryptDestroyKey(key);
    }
};

static BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO gcmInfo(const uint8_t nonce[12], uint8_t* tag) {
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info = {};
    info.cbSize = sizeof(info);
    info.dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;
    info.pbNonce = (PUCHAR)nonce;
    info.cbNonce = 12;
    info.pbTag = tag;
    info.cbTag = 16;
    return info;
}

bool aesGcmEncrypt(const uint8_t key[32], const uint8_t nonce[12],
                   const uint8_t* pt, size_t ptLen, std::string& ctOut) {
    GcmCtx ctx;
    if (!ctx.open(key)) return false;
    std::string buf;
    buf.resize(ptLen + 16);
    uint8_t tag[16];
    auto info = gcmInfo(nonce, tag);
    ULONG done = 0;
    NTSTATUS st = BCryptEncrypt(ctx.key, (PUCHAR)pt, (ULONG)ptLen, &info,
                                nullptr, 0, (PUCHAR)buf.data(), (ULONG)buf.size(),
                                &done, 0);
    if (!BCRYPT_SUCCESS(st) || done != ptLen) return false;
    memcpy(buf.data() + ptLen, tag, 16);
    ctOut.swap(buf);
    return true;
}

bool aesGcmDecrypt(const uint8_t key[32], const uint8_t nonce[12],
                   const uint8_t* ct, size_t ctLen, std::string& ptOut) {
    if (ctLen < 16) return false;
    const size_t ptLen = ctLen - 16;
    GcmCtx ctx;
    if (!ctx.open(key)) return false;
    std::string buf;
    buf.resize(ctLen); // 输出缓冲留足；实际写入 ptLen 字节
    auto info = gcmInfo(nonce, const_cast<uint8_t*>(ct + ptLen)); // 末尾 16 字节即 tag
    ULONG done = 0;
    // CNG 的 cbInput 只传密文体（不含 tag）：tag 由 pbTag 单独参与比对
    NTSTATUS st = BCryptDecrypt(ctx.key, (PUCHAR)ct, (ULONG)ptLen, &info,
                                nullptr, 0, (PUCHAR)buf.data(), (ULONG)buf.size(),
                                &done, 0);
    if (!BCRYPT_SUCCESS(st) || done != ptLen) return false; // 认证失败即失败
    buf.resize(done);
    ptOut.swap(buf);
    return true;
}

} // namespace onetime
