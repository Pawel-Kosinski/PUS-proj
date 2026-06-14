# SecVault - projekt PUS

SecVault to projekt na kurs Programowanie Uslug Sieciowych (PUS), realizowany w architekturze klient-serwer.
System implementuje autorski protokol binarny SVP (SecVault Protocol) dzialajacy po TCP z wymuszonym TLS 1.3.

Kluczowe cechy:
- binarne ramki SVP (naglowek 11B + payload + HMAC),
- bezpieczny transport TLS 1.3,
- zero-knowledge dla danych sejfu (szyfrowanie po stronie klienta),
- wersjonowanie sejfu i optimistic locking (CAS),
- sesje i odswiezanie tokenow,
- opcjonalne 2FA (TOTP).

## Stos technologiczny

- Python 3.13
- `asyncio` (asynchroniczny serwer)
- `cryptography` (HKDF, AES-GCM i prymitywy krypto)
- `aiosqlite` (asynchroniczna baza SQLite)
- `pyotp` (obsluga TOTP)

## Struktura katalogow

- [client-py](client-py) - klient CLI, kryptografia po stronie klienta, REPL i synchronizacja sejfu.
- [server-py](server-py) - serwer `asyncio`, TLS 1.3, maszyna stanow SVP, baza SQLite i testy integracyjne.

## Quick Start

1. Przejdz do [server-py](server-py) i wykonaj instrukcje z [server-py/README.md](server-py/README.md):
   - seed uzytkownika testowego,
   - uruchomienie serwera.
2. W drugim terminalu przejdz do [client-py](client-py) i wykonaj instrukcje z [client-py/README.md](client-py/README.md):
   - uruchomienie klienta CLI z `--insecure` do testow lokalnych,
   - manualny scenariusz E2E (logowanie, `add`, `sync`, `pull`, `ping`, `quit`).

## Dokumentacja szczegolowa

- Specyfikacja protokolu: [SecVault_etap1.md](SecVault_etap1.md)
- Projekt aplikacji i przypadki uzycia: [SecVault_etap2.md](SecVault_etap2.md)
