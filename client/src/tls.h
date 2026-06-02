// tls.h - warstwa transportu: gniazdo TCP opakowane w TLS 1.3 (OpenSSL).
// Klient zawsze inicjuje połączenie; operacje są blokujące (model request-response).
#pragma once
#include <memory>
#include <optional>
#include <string>
#include "bytes.h"
#include "frame.h"

namespace svp {

class TlsError : public std::runtime_error {
public:
    explicit TlsError(const std::string& w) : std::runtime_error(w) {}
};

// Pojedyncze połączenie TLS do serwera SVP. Wysyła i odbiera całe ramki SVP.
class TlsConnection {
public:
    // ca_file: opcjonalny plik CA do weryfikacji certyfikatu serwera.
    // insecure: gdy true, weryfikacja certyfikatu jest wyłączona (środowisko laboratoryjne).
    TlsConnection(const std::string& host, uint16_t port,
                  const std::optional<std::string>& ca_file, bool insecure, bool debug);
    ~TlsConnection();

    TlsConnection(const TlsConnection&) = delete;
    TlsConnection& operator=(const TlsConnection&) = delete;

    // Wysyła ramkę (z trailerem HMAC liczonym z k_mac, jeśli podano).
    void send_frame(const Frame& f, const std::optional<Bytes>& k_mac);

    // Odbiera kolejną ramkę. Jeśli podano k_mac, weryfikuje HMAC (niezgodność -> FrameError).
    Frame recv_frame(const std::optional<Bytes>& k_mac);

    const std::string& peer_cn() const { return peer_cn_; }

private:
    void read_exact(uint8_t* buf, size_t n);
    void write_all(const uint8_t* buf, size_t n);

    struct Impl;
    std::unique_ptr<Impl> p_;
    std::string peer_cn_;
    bool debug_;
};

}  // namespace svp
