// crypto.h - moduł kryptograficzny klienta (opakowanie OpenSSL EVP).
// Cała kryptografia SecVault wykonywana jest po stronie klienta (zero-knowledge).
#pragma once
#include <stdexcept>
#include <string>
#include "bytes.h"

namespace svp::crypto {

// Wyjątek dla błędów warstwy kryptograficznej (np. nieudana weryfikacja GCM_TAG).
class CryptoError : public std::runtime_error {
public:
    explicit CryptoError(const std::string& w) : std::runtime_error(w) {}
};

// Generator losowych bajtów (CSPRNG) - IV, nonce, client_id.
Bytes random_bytes(size_t n);

Bytes sha256(const Bytes& data);

// HMAC-SHA256(key, data).
Bytes hmac_sha256(const Bytes& key, const Bytes& data);

// Porównanie w czasie stałym (ochrona przed atakami czasowymi).
bool const_time_eq(const Bytes& a, const Bytes& b);

// PBKDF2-HMAC-SHA256 - wyprowadzenie klucza z hasła głównego.
Bytes pbkdf2_sha256(const std::string& password, const Bytes& salt, int iters, size_t dklen);

// HKDF-SHA256 - derywacja kluczy podrzędnych (np. K_mac z session_token).
Bytes hkdf_sha256(const Bytes& ikm, const Bytes& salt, const std::string& info, size_t len);

// AES-256-GCM. Zwraca szyfrogram, a tag (16 B) zapisuje do tag_out.
Bytes aes256gcm_encrypt(const Bytes& key, const Bytes& iv, const Bytes& plaintext,
                        const Bytes& aad, Bytes& tag_out);

// AES-256-GCM. Rzuca CryptoError, gdy tag się nie zgadza (naruszenie integralności).
Bytes aes256gcm_decrypt(const Bytes& key, const Bytes& iv, const Bytes& ciphertext,
                        const Bytes& aad, const Bytes& tag);

std::string to_hex(const Bytes& b);

}  // namespace svp::crypto
