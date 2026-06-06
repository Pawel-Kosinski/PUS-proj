"""vault.py - sejf w pamięci RAM: wpisy (CRUD), (de)serializacja plaintextu,
szyfrowanie AES-256-GCM oraz scalanie przy konflikcie wersji (UC-04).

Format plaintextu jest identyczny jak w wersji C++ (client/src/vault.cpp), więc sejf
zaszyfrowany jednym klientem odszyfruje drugi.
"""
import time

import protocol
import svpcrypto as crypto
from framing import ByteReader, ByteWriter

_MAGIC = b"SVVAULT1"


class Entry:
    def __init__(self, id="", service="", username="", password="", notes="", updated_at=0):
        self.id = id
        self.service = service
        self.username = username
        self.password = password
        self.notes = notes
        self.updated_at = updated_at


class Vault:
    def __init__(self):
        self.entries = []

    # --- operacje na wpisach ---
    def add(self, service, username, password, notes=""):
        e = Entry(id=crypto.to_hex(crypto.random_bytes(8)), service=service, username=username,
                  password=password, notes=notes, updated_at=int(time.time()))
        self.entries.append(e)
        return e

    def find_by_service(self, service):
        for e in self.entries:
            if e.service == service:
                return e
        return None

    def find_by_id(self, id):
        for e in self.entries:
            if e.id == id:
                return e
        return None

    def find(self, key):
        return self.find_by_service(key) or self.find_by_id(key)

    def remove(self, id_or_service):
        for i, e in enumerate(self.entries):
            if e.id == id_or_service or e.service == id_or_service:
                del self.entries[i]
                return True
        return False

    def __len__(self):
        return len(self.entries)

    # --- serializacja plaintextu (format wewnętrzny klienta; serwer go nie widzi) ---
    def serialize_plaintext(self) -> bytes:
        w = ByteWriter()
        w.raw(_MAGIC)
        w.u32(len(self.entries))
        for e in self.entries:
            w.lpstr(e.id)
            w.lpstr(e.service)
            w.lpstr(e.username)
            w.lpstr(e.password)
            w.lpstr(e.notes)
            w.u64(e.updated_at)
        return w.take()

    @staticmethod
    def deserialize_plaintext(pt: bytes) -> "Vault":
        v = Vault()
        r = ByteReader(pt)
        if r.raw(len(_MAGIC)) != _MAGIC:
            raise ValueError("zły format sejfu (magic) - złe hasło lub uszkodzone dane")
        n = r.u32()
        for _ in range(n):
            e = Entry()
            e.id = r.lpstr()
            e.service = r.lpstr()
            e.username = r.lpstr()
            e.password = r.lpstr()
            e.notes = r.lpstr()
            e.updated_at = r.u64()
            v.entries.append(e)
        return v

    # --- warstwa kryptograficzna sejfu ---
    def encrypt(self, k_vault: bytes) -> bytes:
        """blob = IV(12B) || AES-256-GCM(K_vault, IV, plaintext) || GCM_TAG(16B)."""
        iv = crypto.random_bytes(protocol.GCM_IV_LEN)
        ct_and_tag = crypto.aes256gcm_encrypt(k_vault, iv, self.serialize_plaintext())
        return iv + ct_and_tag

    @staticmethod
    def decrypt(blob: bytes, k_vault: bytes) -> "Vault":
        if len(blob) < protocol.GCM_IV_LEN + protocol.GCM_TAG_LEN:
            raise ValueError("blob sejfu za krótki")
        iv = blob[:protocol.GCM_IV_LEN]
        ct_and_tag = blob[protocol.GCM_IV_LEN:]
        pt = crypto.aes256gcm_decrypt(k_vault, iv, ct_and_tag)
        return Vault.deserialize_plaintext(pt)

    # --- scalanie konfliktu (UC-04) ---
    def merge_from(self, server: "Vault"):
        """Łączy wpisy po id; przy kolizji wybiera nowszy (updated_at). Serwer wygrywa remis.
        Zwraca listę serwisów/identyfikatorów, dla których wykryto konflikt."""
        by_id = {e.id: e for e in self.entries}  # zmiany lokalne
        conflicts = []
        for s in server.entries:
            local = by_id.get(s.id)
            if local is None:
                by_id[s.id] = s  # wpis tylko po stronie serwera
            else:
                differ = (local.service != s.service or local.username != s.username or
                          local.password != s.password or local.notes != s.notes)
                if differ:
                    conflicts.append(s.service or s.id)
                    if s.updated_at >= local.updated_at:
                        by_id[s.id] = s
        self.entries = list(by_id.values())
        return conflicts
