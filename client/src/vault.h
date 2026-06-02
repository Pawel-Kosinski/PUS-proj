// vault.h - sejf w pamięci RAM: wpisy (CRUD), (de)serializacja plaintextu,
// szyfrowanie AES-256-GCM oraz scalanie przy konflikcie wersji (UC-04).
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "bytes.h"

namespace svp {

struct Entry {
    std::string id;        // losowy identyfikator (do scalania)
    std::string service;   // np. "github.com"
    std::string username;
    std::string password;
    std::string notes;
    uint64_t updated_at = 0;  // unix sekundy - do rozstrzygania konfliktów
};

class Vault {
public:
    // --- operacje na wpisach (UC-02/03, komendy CLI) ---
    Entry& add(const std::string& service, const std::string& username,
               const std::string& password, const std::string& notes);
    Entry* find_by_service(const std::string& service);  // pierwszy pasujący, nullptr gdy brak
    Entry* find_by_id(const std::string& id);
    bool remove(const std::string& id_or_service);
    const std::vector<Entry>& entries() const { return entries_; }
    size_t size() const { return entries_.size(); }

    // --- serializacja plaintextu (format wewnętrzny klienta; serwer go nie widzi) ---
    Bytes serialize_plaintext() const;
    static Vault deserialize_plaintext(const Bytes& pt);

    // --- warstwa kryptograficzna sejfu ---
    // blob = IV(12B) || ciphertext || GCM_TAG(16B), szyfrowany kluczem K_vault.
    Bytes encrypt(const Bytes& k_vault) const;
    static Vault decrypt(const Bytes& blob, const Bytes& k_vault);

    // Scalanie z wersją serwerową (UC-04): łączy wpisy po id, przy kolizji
    // wybiera nowszy (updated_at). Zwraca liczbę wykrytych konfliktów.
    int merge_from(const Vault& server, std::vector<std::string>& conflicts);

private:
    std::vector<Entry> entries_;
};

}  // namespace svp
