// bytes.h - typ Bytes oraz pomocnicze klasy do (de)serializacji binarnej.
// Kodowanie liczb: little-endian, unsigned (zgodnie z kontraktem SVP).
#pragma once
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace svp {

using Bytes = std::vector<uint8_t>;

inline Bytes to_bytes(const std::string& s) {
    return Bytes(s.begin(), s.end());
}
inline std::string to_string(const Bytes& b) {
    return std::string(b.begin(), b.end());
}

// Zapis pól do bufora bajtów (little-endian).
class ByteWriter {
public:
    void u8(uint8_t v) { buf_.push_back(v); }
    void u16(uint16_t v) { put_le(v, 2); }
    void u32(uint32_t v) { put_le(v, 4); }
    void u64(uint64_t v) { put_le(v, 8); }

    // Surowe bajty o stałej długości.
    void raw(const uint8_t* p, size_t n) { buf_.insert(buf_.end(), p, p + n); }
    void raw(const Bytes& b) { buf_.insert(buf_.end(), b.begin(), b.end()); }

    // Pole zmiennej długości z prefiksem uint16 (do 64 KiB) - dla łańcuchów/krótkich blobów.
    void lpstr(const std::string& s) {
        if (s.size() > 0xFFFF) throw std::length_error("lpstr za długi");
        u16(static_cast<uint16_t>(s.size()));
        buf_.insert(buf_.end(), s.begin(), s.end());
    }
    void lpbytes(const Bytes& b) {
        if (b.size() > 0xFFFF) throw std::length_error("lpbytes za długi");
        u16(static_cast<uint16_t>(b.size()));
        raw(b);
    }
    // Pole zmiennej długości z prefiksem uint32 - dla dużych blobów (sejf).
    void lpblob(const Bytes& b) {
        u32(static_cast<uint32_t>(b.size()));
        raw(b);
    }

    const Bytes& data() const { return buf_; }
    Bytes take() { return std::move(buf_); }

private:
    void put_le(uint64_t v, int n) {
        for (int i = 0; i < n; ++i) buf_.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
    }
    Bytes buf_;
};

// Odczyt pól z bufora bajtów (little-endian). Rzuca std::out_of_range przy niedoborze danych.
class ByteReader {
public:
    explicit ByteReader(const Bytes& b) : buf_(b) {}

    uint8_t u8() { need(1); return buf_[pos_++]; }
    uint16_t u16() { return static_cast<uint16_t>(get_le(2)); }
    uint32_t u32() { return static_cast<uint32_t>(get_le(4)); }
    uint64_t u64() { return get_le(8); }

    Bytes raw(size_t n) {
        need(n);
        Bytes r(buf_.begin() + pos_, buf_.begin() + pos_ + n);
        pos_ += n;
        return r;
    }
    std::string lpstr() {
        size_t n = u16();
        need(n);
        std::string s(buf_.begin() + pos_, buf_.begin() + pos_ + n);
        pos_ += n;
        return s;
    }
    Bytes lpbytes() { return raw(u16()); }
    Bytes lpblob() { return raw(u32()); }

    size_t remaining() const { return buf_.size() - pos_; }

private:
    void need(size_t n) {
        if (pos_ + n > buf_.size()) throw std::out_of_range("ByteReader: za mało danych");
    }
    uint64_t get_le(int n) {
        need(n);
        uint64_t v = 0;
        for (int i = 0; i < n; ++i) v |= static_cast<uint64_t>(buf_[pos_ + i]) << (8 * i);
        pos_ += n;
        return v;
    }
    const Bytes& buf_;
    size_t pos_ = 0;
};

}  // namespace svp
