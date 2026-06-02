// client.h - menedżer protokołu SVP po stronie klienta: logowanie (UC-01),
// rejestracja, pobranie/zapis sejfu (UC-02/03), wznowienie sesji tokenem (UC-05).
#pragma once
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include "bytes.h"
#include "tls.h"
#include "vault.h"

namespace svp {

// Błąd zwrócony przez serwer w ramce AUTH_FAIL lub ERROR.
class ProtocolError : public std::runtime_error {
public:
    ProtocolError(uint8_t code, const std::string& msg)
        : std::runtime_error(msg), code_(code) {}
    uint8_t code() const { return code_; }
private:
    uint8_t code_;
};

struct ClientConfig {
    std::string host = "127.0.0.1";
    uint16_t port = SVP_PORT;
    std::optional<std::string> ca_file;
    bool insecure = false;
    bool debug = false;
};

class Client {
public:
    explicit Client(ClientConfig cfg);

    // Nawiązuje połączenie TCP+TLS (bez logowania).
    void connect();
    bool connected() const { return conn_ != nullptr; }

    // Wyprowadza klucze z hasła głównego (K_auth do uwierzytelnienia, K_vault do sejfu).
    void derive_keys(const std::string& login, const std::string& password);

    // Pełne logowanie challenge-response (UC-01); opcjonalnie kod TOTP (UC-06).
    // Po sukcesie ustawia session_token, vault_id, vault_version oraz K_mac.
    void login(const std::optional<std::string>& totp_code = std::nullopt);

    // Rejestracja nowego konta (rozszerzenie REGISTER/REGISTER_OK).
    void register_account();

    // Wznowienie sesji ważnym tokenem bez podawania hasła (UC-05).
    void refresh_session();

    // Pobranie sejfu (VAULT_GET -> VAULT_DATA). Zwraca false gdy serwer nie ma sejfu
    // (ERR_NOT_FOUND) - wtedy zostaje pusty, świeży sejf. Aktualizuje vault_version_.
    bool fetch_vault(Bytes& blob_out);

    // Zapis sejfu (VAULT_PUT -> VAULT_ACK). Rzuca ProtocolError(ERR_CONFLICT) przy konflikcie.
    // Po sukcesie aktualizuje vault_version_.
    uint32_t put_vault(const Bytes& blob, uint32_t base_version);

    void ping();
    void bye(uint8_t reason = BYE_NORMAL);

    // Gwarantuje aktywne połączenie i sesję; po zerwaniu łączy ponownie i odświeża token (UC-05).
    void ensure_session();

    // --- akcesory stanu ---
    const std::string& login_name() const { return login_; }
    uint32_t vault_version() const { return vault_version_; }
    const Bytes& vault_id() const { return vault_id_; }
    const Bytes& k_vault() const { return k_vault_; }
    bool has_keys() const { return !k_auth_.empty(); }

private:
    uint32_t next_seq() { return seq_++; }
    void send(uint8_t type, uint8_t flags, const Bytes& payload, bool authed);
    Frame recv(bool authed);                       // odbiera, odpowiada na PING, rzuca na ERROR
    Frame expect(uint8_t type, bool authed);       // jak recv, ale wymusza typ
    Bytes do_challenge();                           // HELLO -> CHALLENGE, zwraca nonce_s
    void compute_kmac();                            // K_mac = HKDF(token, nonce_c, "svp-mac")

    ClientConfig cfg_;
    std::unique_ptr<TlsConnection> conn_;

    std::string login_;
    Bytes k_auth_;        // PBKDF2(password, SHA256(login)) - weryfikator
    Bytes k_vault_;       // PBKDF2(password, SHA256("vault:"+login)) - klucz sejfu (serwer go nie zna)
    Bytes client_id_;     // stały identyfikator klienta w obrębie sesji
    Bytes nonce_c_;       // nonce klienta z bieżącego handshake
    Bytes session_token_; // token sesyjny od serwera
    std::optional<Bytes> k_mac_;  // klucz HMAC ramek po ESTABLISHED
    Bytes vault_id_;
    uint32_t vault_version_ = 0;
    uint64_t token_expiry_ = 0;
    uint32_t seq_ = 0;
};

}  // namespace svp
