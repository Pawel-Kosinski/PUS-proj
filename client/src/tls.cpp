// tls.cpp - implementacja transportu TLS 1.3 na bazie przykładu tls_client.c (PUS-04).
#include "tls.h"

#include <netdb.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <cstdio>
#include <cstring>

#include "crypto.h"

namespace svp {

struct TlsConnection::Impl {
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;
    int sock = -1;

    ~Impl() {
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        if (sock >= 0) close(sock);
        if (ctx) SSL_CTX_free(ctx);
    }
};

namespace {
[[noreturn]] void ssl_fail(const std::string& where) {
    char buf[256] = {0};
    unsigned long e = ERR_get_error();
    if (e) ERR_error_string_n(e, buf, sizeof(buf));
    throw TlsError(where + ": " + buf);
}

int tcp_connect(const std::string& host, uint16_t port) {
    struct addrinfo hints {};
    hints.ai_family = AF_UNSPEC;  // IPv4 lub IPv6
    hints.ai_socktype = SOCK_STREAM;
    std::string port_s = std::to_string(port);

    struct addrinfo* res = nullptr;
    int rc = getaddrinfo(host.c_str(), port_s.c_str(), &hints, &res);
    if (rc != 0) throw TlsError(std::string("getaddrinfo: ") + gai_strerror(rc));

    int sock = -1;
    for (auto* ai = res; ai; ai = ai->ai_next) {
        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock < 0) continue;
        if (connect(sock, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);
    if (sock < 0) throw TlsError("connect: nie udało się połączyć z " + host);
    return sock;
}
}  // namespace

TlsConnection::TlsConnection(const std::string& host, uint16_t port,
                             const std::optional<std::string>& ca_file, bool insecure, bool debug)
    : p_(std::make_unique<Impl>()), debug_(debug) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    p_->ctx = SSL_CTX_new(TLS_client_method());
    if (!p_->ctx) ssl_fail("SSL_CTX_new");
    // Wymuszenie TLS 1.3.
    SSL_CTX_set_min_proto_version(p_->ctx, TLS1_3_VERSION);

    if (insecure) {
        SSL_CTX_set_verify(p_->ctx, SSL_VERIFY_NONE, nullptr);
    } else {
        SSL_CTX_set_verify(p_->ctx, SSL_VERIFY_PEER, nullptr);
        if (ca_file) {
            if (SSL_CTX_load_verify_locations(p_->ctx, ca_file->c_str(), nullptr) != 1)
                ssl_fail("load_verify_locations");
        } else {
            SSL_CTX_set_default_verify_paths(p_->ctx);
        }
    }

    p_->sock = tcp_connect(host, port);

    p_->ssl = SSL_new(p_->ctx);
    if (!p_->ssl) ssl_fail("SSL_new");
    if (SSL_set_fd(p_->ssl, p_->sock) <= 0) ssl_fail("SSL_set_fd");
    // SNI + weryfikacja nazwy hosta (gdy włączona weryfikacja).
    SSL_set_tlsext_host_name(p_->ssl, host.c_str());
    if (!insecure) {
        SSL_set_hostflags(p_->ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        if (SSL_set1_host(p_->ssl, host.c_str()) != 1) ssl_fail("SSL_set1_host");
    }

    if (SSL_connect(p_->ssl) <= 0) ssl_fail("SSL_connect (handshake TLS)");

    // Odczyt CN certyfikatu serwera (informacyjnie / debug).
    X509* cert = SSL_get_peer_certificate(p_->ssl);
    if (cert) {
        char cn[256] = {0};
        X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, cn, sizeof(cn));
        peer_cn_ = cn;
        X509_free(cert);
    }
    if (debug_)
        fprintf(stderr, "[tls] połączono, %s, peer CN=%s\n", SSL_get_version(p_->ssl),
                peer_cn_.c_str());
}

TlsConnection::~TlsConnection() = default;

void TlsConnection::write_all(const uint8_t* buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        int w = SSL_write(p_->ssl, buf + off, static_cast<int>(n - off));
        if (w <= 0) {
            int err = SSL_get_error(p_->ssl, w);
            throw TlsError("SSL_write błąd (kod " + std::to_string(err) + ") - zerwane połączenie");
        }
        off += static_cast<size_t>(w);
    }
}

void TlsConnection::read_exact(uint8_t* buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        int r = SSL_read(p_->ssl, buf + off, static_cast<int>(n - off));
        if (r <= 0) {
            int err = SSL_get_error(p_->ssl, r);
            if (err == SSL_ERROR_ZERO_RETURN)
                throw TlsError("połączenie zamknięte przez serwer (EOF)");
            throw TlsError("SSL_read błąd (kod " + std::to_string(err) + ") - zerwane połączenie");
        }
        off += static_cast<size_t>(r);
    }
}

void TlsConnection::send_frame(const Frame& f, const std::optional<Bytes>& k_mac) {
    Bytes raw = serialize(f, k_mac);
    if (debug_)
        fprintf(stderr, "[tx] %-11s seq=%u flags=0x%02x len=%zu\n", msg_name(f.type), f.seq,
                f.flags, f.payload.size());
    write_all(raw.data(), raw.size());
}

Frame TlsConnection::recv_frame(const std::optional<Bytes>& k_mac) {
    uint8_t hdr[HEADER_LEN];
    read_exact(hdr, HEADER_LEN);

    Frame f;
    f.version = hdr[0];
    f.type = hdr[1];
    f.flags = hdr[2];
    f.seq = static_cast<uint32_t>(hdr[3]) | (static_cast<uint32_t>(hdr[4]) << 8) |
            (static_cast<uint32_t>(hdr[5]) << 16) | (static_cast<uint32_t>(hdr[6]) << 24);
    uint32_t plen = static_cast<uint32_t>(hdr[7]) | (static_cast<uint32_t>(hdr[8]) << 8) |
                    (static_cast<uint32_t>(hdr[9]) << 16) | (static_cast<uint32_t>(hdr[10]) << 24);

    if (f.version != SVP_VERSION) throw FrameError("nieobsługiwana wersja protokołu");
    if (plen > MAX_PAYLOAD) throw FrameError("PAYLOAD_LEN przekracza limit");

    f.payload.resize(plen);
    if (plen) read_exact(f.payload.data(), plen);

    Bytes mac(HMAC_LEN);
    read_exact(mac.data(), HMAC_LEN);

    if (k_mac.has_value()) {
        Bytes signed_part(hdr, hdr + HEADER_LEN);
        signed_part.insert(signed_part.end(), f.payload.begin(), f.payload.end());
        Bytes expect = crypto::hmac_sha256(*k_mac, signed_part);
        if (!crypto::const_time_eq(expect, mac))
            throw FrameError("zła suma HMAC ramki (ERR_BAD_HMAC)");
    }

    if (debug_)
        fprintf(stderr, "[rx] %-11s seq=%u flags=0x%02x len=%zu\n", msg_name(f.type), f.seq,
                f.flags, f.payload.size());
    return f;
}

}  // namespace svp
