"""framing.py - (de)serializacja pól binarnych oraz ramek SVP.

Kodowanie liczb: little-endian, unsigned (zgodnie z kontraktem SVP).
Ramka: nagłówek 11B + PAYLOAD + HMAC-SHA256(32B).
"""
import struct

import protocol
import svpcrypto as crypto

_HEADER = struct.Struct("<BBBII")  # VERSION, TYPE, FLAGS, SEQ_ID, PAYLOAD_LEN


class FrameError(Exception):
    """Błąd warstwy ramkowania (zły nagłówek, zła długość, zły HMAC)."""


class ByteWriter:
    """Zapis pól do bufora bajtów (little-endian)."""

    def __init__(self):
        self._buf = bytearray()

    def u8(self, v):
        self._buf.append(v & 0xFF)

    def u16(self, v):
        self._buf += struct.pack("<H", v)

    def u32(self, v):
        self._buf += struct.pack("<I", v)

    def u64(self, v):
        self._buf += struct.pack("<Q", v)

    def raw(self, b):
        self._buf += b

    def lpstr(self, s):
        """Pole zmiennej długości z prefiksem u16 (łańcuch/krótkie bajty, ≤ 64 KiB)."""
        if isinstance(s, str):
            s = s.encode("utf-8")
        if len(s) > 0xFFFF:
            raise ValueError("lpstr za długi")
        self.u16(len(s))
        self._buf += s

    def lpbytes(self, b):
        if len(b) > 0xFFFF:
            raise ValueError("lpbytes za długi")
        self.u16(len(b))
        self._buf += b

    def lpblob(self, b):
        """Pole zmiennej długości z prefiksem u32 - dla dużych blobów (sejf)."""
        self.u32(len(b))
        self._buf += b

    def take(self) -> bytes:
        return bytes(self._buf)


class ByteReader:
    """Odczyt pól z bufora bajtów (little-endian)."""

    def __init__(self, b: bytes):
        self._buf = b
        self._pos = 0

    def _need(self, n):
        if self._pos + n > len(self._buf):
            raise FrameError("ByteReader: za mało danych")

    def u8(self):
        self._need(1)
        v = self._buf[self._pos]
        self._pos += 1
        return v

    def u16(self):
        self._need(2)
        v = struct.unpack_from("<H", self._buf, self._pos)[0]
        self._pos += 2
        return v

    def u32(self):
        self._need(4)
        v = struct.unpack_from("<I", self._buf, self._pos)[0]
        self._pos += 4
        return v

    def u64(self):
        self._need(8)
        v = struct.unpack_from("<Q", self._buf, self._pos)[0]
        self._pos += 8
        return v

    def raw(self, n):
        self._need(n)
        v = self._buf[self._pos:self._pos + n]
        self._pos += n
        return bytes(v)

    def lpstr(self):
        return self.raw(self.u16()).decode("utf-8")

    def lpbytes(self):
        return self.raw(self.u16())

    def lpblob(self):
        return self.raw(self.u32())

    def remaining(self):
        return len(self._buf) - self._pos


class Frame:
    def __init__(self, type=0, flags=protocol.FLAG_NONE, seq=0, payload=b"",
                 version=protocol.SVP_VERSION):
        self.version = version
        self.type = type
        self.flags = flags
        self.seq = seq
        self.payload = payload


def serialize(frame: Frame, k_mac) -> bytes:
    """Serializuje ramkę. Gdy k_mac jest None (faza przed ustaleniem sesji), trailer to
    32 bajty zerowe - integralność zapewnia wtedy TLS."""
    if len(frame.payload) > protocol.MAX_PAYLOAD:
        raise FrameError("PAYLOAD_LEN > MAX_PAYLOAD")
    hdr = _HEADER.pack(frame.version, frame.type, frame.flags, frame.seq, len(frame.payload))
    body = hdr + frame.payload
    mac = crypto.hmac_sha256(k_mac, body) if k_mac is not None else b"\x00" * protocol.HMAC_LEN
    return body + mac


def parse_header(hdr: bytes):
    """Zwraca (version, type, flags, seq, payload_len) z 11-bajtowego nagłówka."""
    return _HEADER.unpack(hdr)
