// frame.h - (de)serializacja ramek SVP: nagłówek 11B + PAYLOAD + HMAC-SHA256(32B).
#pragma once
#include <cstdint>
#include <optional>
#include "bytes.h"
#include "protocol.h"

namespace svp {

struct Frame {
    uint8_t version = SVP_VERSION;
    uint8_t type = 0;
    uint8_t flags = FLAG_NONE;
    uint32_t seq = 0;
    Bytes payload;
};

// Serializuje ramkę do bajtów. Jeśli podano k_mac, trailer = HMAC(k_mac, nagłówek+payload);
// w przeciwnym razie (faza przed ustaleniem sesji) trailer = 32 bajty zerowe.
Bytes serialize(const Frame& f, const std::optional<Bytes>& k_mac);

// Wyjątek warstwy ramkowania (zły nagłówek, zła długość, zły HMAC).
class FrameError : public std::runtime_error {
public:
    explicit FrameError(const std::string& w) : std::runtime_error(w) {}
};

}  // namespace svp
