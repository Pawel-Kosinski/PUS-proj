// client.cpp - implementacja menedżera protokołu SVP.
#include "client.h"

#include <ctime>

#include "crypto.h"
#include "frame.h"

namespace svp {

namespace {
uint64_t now_sec() { return static_cast<uint64_t>(::time(nullptr)); }
}  // namespace

Client::Client(ClientConfig cfg) : cfg_(std::move(cfg)) {
    client_id_ = crypto::random_bytes(CLIENT_ID_LEN);
}

void Client::connect() {
    conn_ = std::make_unique<TlsConnection>(cfg_.host, cfg_.port, cfg_.ca_file, cfg_.insecure,
                                            cfg_.debug);
    k_mac_.reset();  // nowe połączenie - brak ustalonego K_mac
}

void Client::derive_keys(const std::string& login, const std::string& password) {
    login_ = login;
    Bytes salt_auth = crypto::sha256(to_bytes(login));
    k_auth_ = crypto::pbkdf2_sha256(password, salt_auth, PBKDF2_ITERS, KEY_LEN);
    // Niezależna sól dla klucza sejfu => serwer (znający K_auth) nie wyprowadzi K_vault.
    Bytes salt_vault = crypto::sha256(to_bytes("secvault-vault:" + login));
    k_vault_ = crypto::pbkdf2_sha256(password, salt_vault, PBKDF2_ITERS, KEY_LEN);
}

void Client::send(uint8_t type, uint8_t flags, const Bytes& payload, bool authed) {
    Frame f;
    f.type = type;
    f.flags = flags;
    f.seq = next_seq();
    f.payload = payload;
    conn_->send_frame(f, authed ? k_mac_ : std::optional<Bytes>{});
}

Frame Client::recv(bool authed) {
    for (;;) {
        Frame f = conn_->recv_frame(authed ? k_mac_ : std::optional<Bytes>{});
        if (f.type == MSG_PING) {
            send(MSG_PONG, FLAG_NONE, {}, authed);  // odpowiedź na keep-alive serwera
            continue;
        }
        if (f.type == MSG_ERROR) {
            ByteReader r(f.payload);
            uint8_t code = r.u8();
            std::string msg = r.remaining() ? r.lpstr() : "";
            throw ProtocolError(code, std::string(err_name(code)) + (msg.empty() ? "" : ": " + msg));
        }
        return f;
    }
}

Frame Client::expect(uint8_t type, bool authed) {
    Frame f = recv(authed);
    if (f.type != type)
        throw ProtocolError(ERR_INTERNAL, std::string("oczekiwano ") + msg_name(type) +
                                              ", otrzymano " + msg_name(f.type));
    return f;
}

Bytes Client::do_challenge() {
    nonce_c_ = crypto::random_bytes(NONCE_LEN);
    ByteWriter w;
    w.raw(client_id_);
    w.raw(nonce_c_);
    w.u64(now_sec());
    send(MSG_HELLO, FLAG_NONE, w.take(), /*authed=*/false);

    Frame ch = expect(MSG_CHALLENGE, /*authed=*/false);
    ByteReader r(ch.payload);
    Bytes nonce_s = r.raw(NONCE_LEN);
    return nonce_s;
}

void Client::compute_kmac() {
    k_mac_ = crypto::hkdf_sha256(session_token_, /*salt=*/nonce_c_, "svp-mac", KEY_LEN);
}

void Client::login(const std::optional<std::string>& totp_code) {
    Bytes nonce_s = do_challenge();

    // hmac_resp = HMAC-SHA256(K_auth, nonce_c || nonce_s || login)
    Bytes msg;
    msg.insert(msg.end(), nonce_c_.begin(), nonce_c_.end());
    msg.insert(msg.end(), nonce_s.begin(), nonce_s.end());
    Bytes login_b = to_bytes(login_);
    msg.insert(msg.end(), login_b.begin(), login_b.end());
    Bytes hmac_resp = crypto::hmac_sha256(k_auth_, msg);

    uint8_t flags = FLAG_NONE;
    ByteWriter w;
    w.lpstr(login_);
    w.raw(hmac_resp);
    if (totp_code) {
        flags |= FLAG_TOTP_PRESENT;
        w.lpstr(*totp_code);
    }
    send(MSG_AUTH, flags, w.take(), /*authed=*/false);

    Frame ok = expect(MSG_AUTH_OK, /*authed=*/false);
    ByteReader r(ok.payload);
    session_token_ = r.lpbytes();
    token_expiry_ = r.u64();
    vault_id_ = r.raw(VAULT_ID_LEN);
    vault_version_ = r.u32();
    compute_kmac();
}

void Client::register_account() {
    ByteWriter w;
    w.lpstr(login_);
    w.raw(k_auth_);  // serwer zapisuje K_auth jako weryfikator (przesyłane w tunelu TLS)
    send(MSG_REGISTER, FLAG_NONE, w.take(), /*authed=*/false);

    Frame ok = expect(MSG_REGISTER_OK, /*authed=*/false);
    ByteReader r(ok.payload);
    vault_id_ = r.raw(VAULT_ID_LEN);
    vault_version_ = 0;
}

void Client::refresh_session() {
    Bytes nonce_s = do_challenge();
    (void)nonce_s;  // przy odświeżaniu tokenem nie liczymy hmac_resp

    ByteWriter w;
    w.lpstr(login_);
    w.lpbytes(session_token_);
    send(MSG_AUTH, FLAG_TOKEN_REFRESH, w.take(), /*authed=*/false);

    Frame ok = expect(MSG_AUTH_OK, /*authed=*/false);
    ByteReader r(ok.payload);
    session_token_ = r.lpbytes();
    token_expiry_ = r.u64();
    vault_id_ = r.raw(VAULT_ID_LEN);
    vault_version_ = r.u32();
    compute_kmac();
}

bool Client::fetch_vault(Bytes& blob_out) {
    ByteWriter w;
    w.raw(vault_id_);
    w.u32(vault_version_);
    send(MSG_VAULT_GET, FLAG_NONE, w.take(), /*authed=*/true);

    try {
        Frame data = expect(MSG_VAULT_DATA, /*authed=*/true);
        ByteReader r(data.payload);
        r.raw(VAULT_ID_LEN);  // vault_id (pomijamy - znamy własny)
        vault_version_ = r.u32();
        blob_out = r.lpblob();
        return true;
    } catch (const ProtocolError& e) {
        if (e.code() == ERR_NOT_FOUND) return false;  // brak sejfu - zaczynamy pusty
        throw;
    }
}

uint32_t Client::put_vault(const Bytes& blob, uint32_t base_version) {
    ByteWriter w;
    w.raw(vault_id_);
    w.u32(base_version);
    w.lpblob(blob);
    send(MSG_VAULT_PUT, FLAG_NONE, w.take(), /*authed=*/true);

    Frame ack = expect(MSG_VAULT_ACK, /*authed=*/true);  // ERR_CONFLICT poleci jako ProtocolError
    ByteReader r(ack.payload);
    r.raw(VAULT_ID_LEN);
    vault_version_ = r.u32();
    return vault_version_;
}

void Client::ping() {
    send(MSG_PING, FLAG_NONE, {}, /*authed=*/true);
    expect(MSG_PONG, /*authed=*/true);
}

void Client::bye(uint8_t reason) {
    if (!conn_) return;
    try {
        ByteWriter w;
        w.u8(reason);
        send(MSG_BYE, FLAG_NONE, w.take(), /*authed=*/k_mac_.has_value());
    } catch (...) {
        // grzeczne zamknięcie - ignorujemy błędy zapisu
    }
    conn_.reset();
}

void Client::ensure_session() {
    if (conn_) {
        try {
            ping();  // szybki test żywotności połączenia
            return;
        } catch (...) {
            conn_.reset();  // połączenie martwe - odbudujemy poniżej
        }
    }
    // Reconnect + wznowienie sesji tokenem (UC-05). Gdy token wygasł -> pełne logowanie.
    connect();
    try {
        refresh_session();
    } catch (const ProtocolError& e) {
        if (e.code() == ERR_SESSION_EXPIRED && has_keys()) {
            login();  // token nieważny, ale mamy klucze z hasła w pamięci sesji
        } else {
            throw;
        }
    }
}

}  // namespace svp
