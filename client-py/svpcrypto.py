"""svpcrypto.py - moduł kryptograficzny klienta.

Cała kryptografia SecVault wykonywana jest po stronie klienta (model zero-knowledge).
Prymitywy:
  - PBKDF2 / HMAC / SHA-256 - biblioteka standardowa (hashlib, hmac),
  - AES-256-GCM / HKDF      - pakiet cryptography (PyCA).
Algorytmy i parametry są identyczne jak w wersji C++ (client/src/crypto.cpp).
"""
import hashlib
import hmac
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class CryptoError(Exception):
    """Błąd warstwy kryptograficznej (np. nieudana weryfikacja GCM_TAG)."""


def random_bytes(n: int) -> bytes:
    """Losowe bajty z CSPRNG (IV, nonce, client_id)."""
    return secrets.token_bytes(n)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def const_time_eq(a: bytes, b: bytes) -> bool:
    """Porównanie w czasie stałym (ochrona przed atakami czasowymi)."""
    return hmac.compare_digest(a, b)


def pbkdf2_sha256(password: str, salt: bytes, iters: int, dklen: int) -> bytes:
    """PBKDF2-HMAC-SHA256 - wyprowadzenie klucza z hasła głównego."""
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters, dklen)


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256 - derywacja kluczy podrzędnych (np. K_mac z session_token)."""
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def aes256gcm_encrypt(key: bytes, iv: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """AES-256-GCM. Zwraca ciphertext || tag (16B doklejony na końcu przez AESGCM)."""
    return AESGCM(key).encrypt(iv, plaintext, aad if aad else None)


def aes256gcm_decrypt(key: bytes, iv: bytes, ct_and_tag: bytes, aad: bytes = b"") -> bytes:
    """AES-256-GCM. Rzuca CryptoError, gdy tag się nie zgadza (naruszenie integralności)."""
    try:
        return AESGCM(key).decrypt(iv, ct_and_tag, aad if aad else None)
    except InvalidTag:
        raise CryptoError("AES-GCM: weryfikacja tagu nieudana (uszkodzone/podmienione dane)")


def to_hex(b: bytes) -> str:
    return b.hex()
