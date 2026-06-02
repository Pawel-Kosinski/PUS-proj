// vault.cpp - implementacja sejfu klienta.
#include "vault.h"

#include <ctime>
#include <unordered_map>

#include "crypto.h"
#include "protocol.h"

namespace svp {

namespace {
constexpr char MAGIC[8] = {'S', 'V', 'V', 'A', 'U', 'L', 'T', '1'};

uint64_t now_sec() { return static_cast<uint64_t>(::time(nullptr)); }

std::string new_id() { return crypto::to_hex(crypto::random_bytes(8)); }
}  // namespace

Entry& Vault::add(const std::string& service, const std::string& username,
                  const std::string& password, const std::string& notes) {
    Entry e;
    e.id = new_id();
    e.service = service;
    e.username = username;
    e.password = password;
    e.notes = notes;
    e.updated_at = now_sec();
    entries_.push_back(std::move(e));
    return entries_.back();
}

Entry* Vault::find_by_service(const std::string& service) {
    for (auto& e : entries_)
        if (e.service == service) return &e;
    return nullptr;
}

Entry* Vault::find_by_id(const std::string& id) {
    for (auto& e : entries_)
        if (e.id == id) return &e;
    return nullptr;
}

bool Vault::remove(const std::string& id_or_service) {
    for (auto it = entries_.begin(); it != entries_.end(); ++it) {
        if (it->id == id_or_service || it->service == id_or_service) {
            entries_.erase(it);
            return true;
        }
    }
    return false;
}

Bytes Vault::serialize_plaintext() const {
    ByteWriter w;
    w.raw(reinterpret_cast<const uint8_t*>(MAGIC), sizeof(MAGIC));
    w.u32(static_cast<uint32_t>(entries_.size()));
    for (const auto& e : entries_) {
        w.lpstr(e.id);
        w.lpstr(e.service);
        w.lpstr(e.username);
        w.lpstr(e.password);
        w.lpstr(e.notes);
        w.u64(e.updated_at);
    }
    return w.take();
}

Vault Vault::deserialize_plaintext(const Bytes& pt) {
    Vault v;
    ByteReader r(pt);
    Bytes magic = r.raw(sizeof(MAGIC));
    if (std::memcmp(magic.data(), MAGIC, sizeof(MAGIC)) != 0)
        throw std::runtime_error("zły format sejfu (magic) - złe hasło lub uszkodzone dane");
    uint32_t n = r.u32();
    for (uint32_t i = 0; i < n; ++i) {
        Entry e;
        e.id = r.lpstr();
        e.service = r.lpstr();
        e.username = r.lpstr();
        e.password = r.lpstr();
        e.notes = r.lpstr();
        e.updated_at = r.u64();
        v.entries_.push_back(std::move(e));
    }
    return v;
}

Bytes Vault::encrypt(const Bytes& k_vault) const {
    Bytes iv = crypto::random_bytes(GCM_IV_LEN);
    Bytes tag;
    Bytes ct = crypto::aes256gcm_encrypt(k_vault, iv, serialize_plaintext(), /*aad=*/{}, tag);

    Bytes blob;
    blob.reserve(iv.size() + ct.size() + tag.size());
    blob.insert(blob.end(), iv.begin(), iv.end());
    blob.insert(blob.end(), ct.begin(), ct.end());
    blob.insert(blob.end(), tag.begin(), tag.end());
    return blob;
}

Vault Vault::decrypt(const Bytes& blob, const Bytes& k_vault) {
    if (blob.size() < GCM_IV_LEN + GCM_TAG_LEN)
        throw std::runtime_error("blob sejfu za krótki");
    Bytes iv(blob.begin(), blob.begin() + GCM_IV_LEN);
    Bytes tag(blob.end() - GCM_TAG_LEN, blob.end());
    Bytes ct(blob.begin() + GCM_IV_LEN, blob.end() - GCM_TAG_LEN);
    Bytes pt = crypto::aes256gcm_decrypt(k_vault, iv, ct, /*aad=*/{}, tag);
    return deserialize_plaintext(pt);
}

int Vault::merge_from(const Vault& server, std::vector<std::string>& conflicts) {
    std::unordered_map<std::string, Entry> by_id;
    for (const auto& e : entries_) by_id[e.id] = e;  // zmiany lokalne

    int n_conflict = 0;
    for (const auto& s : server.entries_) {
        auto it = by_id.find(s.id);
        if (it == by_id.end()) {
            by_id[s.id] = s;  // wpis tylko po stronie serwera
        } else {
            const Entry& local = it->second;
            bool differ = local.service != s.service || local.username != s.username ||
                          local.password != s.password || local.notes != s.notes;
            if (differ) {
                ++n_conflict;
                conflicts.push_back(s.service.empty() ? s.id : s.service);
                // Strategia: wybierz nowszy wpis (updated_at). Serwer wygrywa przy remisie.
                if (s.updated_at >= local.updated_at) it->second = s;
            }
        }
    }

    entries_.clear();
    for (auto& kv : by_id) entries_.push_back(std::move(kv.second));
    return n_conflict;
}

}  // namespace svp
