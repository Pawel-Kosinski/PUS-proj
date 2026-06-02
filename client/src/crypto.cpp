// crypto.cpp - implementacja modułu kryptograficznego na OpenSSL 3.0 (EVP/KDF).
#include "crypto.h"

#include "protocol.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <cstdio>

namespace svp::crypto {

namespace {
[[noreturn]] void fail(const std::string& where) {
    char buf[256] = {0};
    unsigned long e = ERR_get_error();
    if (e) ERR_error_string_n(e, buf, sizeof(buf));
    throw CryptoError(where + ": " + buf);
}
}  // namespace

Bytes random_bytes(size_t n) {
    Bytes out(n);
    if (RAND_bytes(out.data(), static_cast<int>(n)) != 1) fail("RAND_bytes");
    return out;
}

Bytes sha256(const Bytes& data) {
    Bytes out(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), out.data());
    return out;
}

Bytes hmac_sha256(const Bytes& key, const Bytes& data) {
    Bytes out(EVP_MAX_MD_SIZE);
    unsigned int len = 0;
    if (!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(), data.size(),
              out.data(), &len))
        fail("HMAC");
    out.resize(len);
    return out;
}

bool const_time_eq(const Bytes& a, const Bytes& b) {
    if (a.size() != b.size()) return false;
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

Bytes pbkdf2_sha256(const std::string& password, const Bytes& salt, int iters, size_t dklen) {
    Bytes out(dklen);
    if (PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.size()), salt.data(),
                          static_cast<int>(salt.size()), iters, EVP_sha256(),
                          static_cast<int>(dklen), out.data()) != 1)
        fail("PBKDF2");
    return out;
}

Bytes hkdf_sha256(const Bytes& ikm, const Bytes& salt, const std::string& info, size_t len) {
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf) fail("EVP_KDF_fetch");
    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx) fail("EVP_KDF_CTX_new");

    OSSL_PARAM params[5];
    int p = 0;
    char digest[] = "SHA256";
    params[p++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0);
    params[p++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                                    const_cast<uint8_t*>(ikm.data()), ikm.size());
    params[p++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                    const_cast<uint8_t*>(salt.data()), salt.size());
    params[p++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                                    const_cast<char*>(info.data()), info.size());
    params[p] = OSSL_PARAM_construct_end();

    Bytes out(len);
    if (EVP_KDF_derive(kctx, out.data(), out.size(), params) != 1) {
        EVP_KDF_CTX_free(kctx);
        fail("EVP_KDF_derive(HKDF)");
    }
    EVP_KDF_CTX_free(kctx);
    return out;
}

Bytes aes256gcm_encrypt(const Bytes& key, const Bytes& iv, const Bytes& plaintext,
                        const Bytes& aad, Bytes& tag_out) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) fail("EVP_CIPHER_CTX_new");
    Bytes ct(plaintext.size());
    int len = 0, ct_len = 0;
    try {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
            fail("EncryptInit(gcm)");
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1)
            fail("set ivlen");
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1)
            fail("EncryptInit(key)");
        if (!aad.empty() &&
            EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1)
            fail("EncryptUpdate(aad)");
        if (EVP_EncryptUpdate(ctx, ct.data(), &len, plaintext.data(),
                              static_cast<int>(plaintext.size())) != 1)
            fail("EncryptUpdate");
        ct_len = len;
        if (EVP_EncryptFinal_ex(ctx, ct.data() + ct_len, &len) != 1) fail("EncryptFinal");
        ct_len += len;
        tag_out.resize(GCM_TAG_LEN);
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag_out.data()) != 1)
            fail("get tag");
    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }
    EVP_CIPHER_CTX_free(ctx);
    ct.resize(ct_len);
    return ct;
}

Bytes aes256gcm_decrypt(const Bytes& key, const Bytes& iv, const Bytes& ciphertext,
                        const Bytes& aad, const Bytes& tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) fail("EVP_CIPHER_CTX_new");
    Bytes pt(ciphertext.size());
    int len = 0, pt_len = 0;
    try {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
            fail("DecryptInit(gcm)");
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1)
            fail("set ivlen");
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1)
            fail("DecryptInit(key)");
        if (!aad.empty() &&
            EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1)
            fail("DecryptUpdate(aad)");
        if (EVP_DecryptUpdate(ctx, pt.data(), &len, ciphertext.data(),
                              static_cast<int>(ciphertext.size())) != 1)
            fail("DecryptUpdate");
        pt_len = len;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()),
                                const_cast<uint8_t*>(tag.data())) != 1)
            fail("set tag");
        // Final zwraca błąd, gdy tag uwierzytelniający się nie zgadza.
        // (czyszczenie ctx wykona blok catch poniżej)
        if (EVP_DecryptFinal_ex(ctx, pt.data() + pt_len, &len) != 1)
            throw CryptoError("AES-GCM: weryfikacja tagu nieudana (uszkodzone/podmienione dane)");
        pt_len += len;
    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }
    EVP_CIPHER_CTX_free(ctx);
    pt.resize(pt_len);
    return pt;
}

std::string to_hex(const Bytes& b) {
    static const char* h = "0123456789abcdef";
    std::string s;
    s.reserve(b.size() * 2);
    for (uint8_t c : b) {
        s.push_back(h[c >> 4]);
        s.push_back(h[c & 0xF]);
    }
    return s;
}

}  // namespace svp::crypto
