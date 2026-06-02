// frame.cpp - serializacja ramki SVP wraz z trailerem HMAC.
#include "frame.h"
#include "crypto.h"

namespace svp {

Bytes serialize(const Frame& f, const std::optional<Bytes>& k_mac) {
    if (f.payload.size() > MAX_PAYLOAD) throw FrameError("PAYLOAD_LEN > MAX_PAYLOAD");

    ByteWriter w;
    w.u8(f.version);
    w.u8(f.type);
    w.u8(f.flags);
    w.u32(f.seq);
    w.u32(static_cast<uint32_t>(f.payload.size()));
    w.raw(f.payload);
    Bytes hdr_and_payload = w.take();  // nagłówek (11B) + payload

    Bytes mac;
    if (k_mac.has_value()) {
        mac = crypto::hmac_sha256(*k_mac, hdr_and_payload);  // 32B
    } else {
        mac.assign(HMAC_LEN, 0);  // przed ustaleniem K_mac - integralność zapewnia TLS
    }

    Bytes out = std::move(hdr_and_payload);
    out.insert(out.end(), mac.begin(), mac.end());
    return out;
}

}  // namespace svp
