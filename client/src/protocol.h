// protocol.h - stałe protokołu SecVault (SVP v1.0): typy komunikatów, flagi,
// kody błędów oraz parametry kryptograficzne. Wspólny kontrakt klient<->serwer.
#pragma once
#include <cstdint>

namespace svp {

constexpr uint8_t SVP_VERSION = 0x01;
constexpr uint16_t SVP_PORT = 7443;

// Stały nagłówek ramki: VERSION(1) | MSG_TYPE(1) | FLAGS(1) | SEQ_ID(4) | PAYLOAD_LEN(4)
constexpr size_t HEADER_LEN = 11;
constexpr size_t HMAC_LEN = 32;        // trailer HMAC-SHA256
constexpr uint32_t MAX_PAYLOAD = 1u << 20;  // 1 MiB na ramkę (TS-06)

enum MsgType : uint8_t {
    MSG_HELLO       = 0x01,
    MSG_CHALLENGE   = 0x02,
    MSG_AUTH        = 0x03,
    MSG_AUTH_OK     = 0x04,
    MSG_AUTH_FAIL   = 0x05,
    MSG_REGISTER    = 0x06,  // rozszerzenie: rejestracja konta z CLI
    MSG_REGISTER_OK = 0x07,
    MSG_VAULT_GET   = 0x10,
    MSG_VAULT_DATA  = 0x11,
    MSG_VAULT_PUT   = 0x12,
    MSG_VAULT_ACK   = 0x13,
    MSG_VAULT_SYNC  = 0x14,
    MSG_PING        = 0x20,
    MSG_PONG        = 0x21,
    MSG_BYE         = 0x2E,
    MSG_ERROR       = 0x2F,
};

enum Flags : uint8_t {
    FLAG_NONE         = 0x00,
    FLAG_FRAGMENTED   = 0x01,
    FLAG_LAST_FRAG    = 0x02,
    FLAG_COMPRESSED   = 0x04,
    FLAG_TOTP_PRESENT = 0x08,
    FLAG_TOKEN_REFRESH= 0x10,
};

enum ErrCode : uint8_t {
    ERR_AUTH_FAILED     = 0x01,
    ERR_RATE_LIMITED    = 0x02,
    ERR_CLOCK_SKEW      = 0x03,
    ERR_CONFLICT        = 0x04,
    ERR_NOT_FOUND       = 0x05,
    ERR_TOO_LARGE       = 0x06,
    ERR_SESSION_EXPIRED = 0x07,
    ERR_FORBIDDEN       = 0x08,
    ERR_UNKNOWN_TYPE    = 0x09,
    ERR_BAD_HMAC        = 0x0A,
    ERR_INTERNAL        = 0xFF,
};

enum ByeReason : uint8_t {
    BYE_NORMAL   = 0x00,
    BYE_TIMEOUT  = 0x01,
    BYE_SHUTDOWN = 0x02,
};

// Parametry kryptografii (zgodne z planem aplikacji).
constexpr int    PBKDF2_ITERS = 200000;
constexpr size_t KEY_LEN      = 32;   // AES-256 / HMAC-SHA256
constexpr size_t NONCE_LEN    = 16;
constexpr size_t CLIENT_ID_LEN= 16;
constexpr size_t VAULT_ID_LEN = 16;
constexpr size_t GCM_IV_LEN   = 12;
constexpr size_t GCM_TAG_LEN  = 16;

inline const char* err_name(uint8_t c) {
    switch (c) {
        case ERR_AUTH_FAILED:     return "ERR_AUTH_FAILED";
        case ERR_RATE_LIMITED:    return "ERR_RATE_LIMITED";
        case ERR_CLOCK_SKEW:      return "ERR_CLOCK_SKEW";
        case ERR_CONFLICT:        return "ERR_CONFLICT";
        case ERR_NOT_FOUND:       return "ERR_NOT_FOUND";
        case ERR_TOO_LARGE:       return "ERR_TOO_LARGE";
        case ERR_SESSION_EXPIRED: return "ERR_SESSION_EXPIRED";
        case ERR_FORBIDDEN:       return "ERR_FORBIDDEN";
        case ERR_UNKNOWN_TYPE:    return "ERR_UNKNOWN_TYPE";
        case ERR_BAD_HMAC:        return "ERR_BAD_HMAC";
        case ERR_INTERNAL:        return "ERR_INTERNAL";
        default:                  return "ERR_UNKNOWN";
    }
}

inline const char* msg_name(uint8_t t) {
    switch (t) {
        case MSG_HELLO:       return "HELLO";
        case MSG_CHALLENGE:   return "CHALLENGE";
        case MSG_AUTH:        return "AUTH";
        case MSG_AUTH_OK:     return "AUTH_OK";
        case MSG_AUTH_FAIL:   return "AUTH_FAIL";
        case MSG_REGISTER:    return "REGISTER";
        case MSG_REGISTER_OK: return "REGISTER_OK";
        case MSG_VAULT_GET:   return "VAULT_GET";
        case MSG_VAULT_DATA:  return "VAULT_DATA";
        case MSG_VAULT_PUT:   return "VAULT_PUT";
        case MSG_VAULT_ACK:   return "VAULT_ACK";
        case MSG_VAULT_SYNC:  return "VAULT_SYNC";
        case MSG_PING:        return "PING";
        case MSG_PONG:        return "PONG";
        case MSG_BYE:         return "BYE";
        case MSG_ERROR:       return "ERROR";
        default:              return "UNKNOWN";
    }
}

}  // namespace svp
