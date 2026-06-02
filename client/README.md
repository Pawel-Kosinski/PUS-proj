# SecVault — klient (C++)

Klient CLI menedżera haseł SecVault, mówiący protokołem **SVP v1.0** przez TCP+TLS 1.3.
Cała kryptografia działa po stronie klienta (model zero-knowledge): serwer nigdy nie
poznaje hasła głównego ani odszyfrowanej zawartości sejfu.

## Budowanie

Wymagania: `g++` (C++17), `OpenSSL 3.x` (`libssl-dev`).

```bash
make            # buduje ./secvault
make test       # self-test kryptografii (KAT + roundtrip, bez serwera)
```

## Uruchomienie

```bash
./secvault --host 127.0.0.1 --port 7443 [--ca ca.pem] [--insecure] \
           [--cache .svp_cache] [--offline] [--debug]
```

- `--insecure` — wyłącza weryfikację certyfikatu (laboratorium / cert self-signed).
- `--ca plik.pem` — CA do weryfikacji certyfikatu serwera.
- `--offline` — praca na lokalnej, zaszyfrowanej kopii sejfu (tylko odczyt).
- `--debug` — hex/metadane ramek SVP (tx/rx) na stderr.

Po starcie: nazwa użytkownika + hasło główne (bez echa), następnie REPL:

```
ls · get <serwis|id> · add · edit <serwis|id> · rm <serwis|id>
sync · pull · ping · help · quit
```

## Realizowane przypadki użycia

| UC | Opis | Gdzie |
|----|------|-------|
| UC-01 | Logowanie challenge-response (PBKDF2 + HMAC) | `Client::login` |
| UC-02 | Pobranie i deszyfracja sejfu | `Client::fetch_vault`, `Vault::decrypt` |
| UC-03 | Zapis sejfu (optimistic locking, `base_version`) | `Client::put_vault`, `do_sync` |
| UC-04 | Konflikt wersji → scalanie → ponowny PUT | `Vault::merge_from`, `do_sync` |
| UC-05 | Wznowienie sesji tokenem po zerwaniu | `Client::ensure_session` / `refresh_session` |
| UC-06 | TOTP (pole w AUTH) | flaga `FLAG_TOTP_PRESENT` w `Client::login` |
| REGISTER | Rejestracja konta z CLI (rozszerzenie) | `Client::register_account` |

## Struktura

```
src/bytes.h      — (de)serializacja LE, ByteWriter/ByteReader
src/protocol.h   — stałe SVP (typy, flagi, kody błędów, parametry krypto)
src/crypto.*     — OpenSSL: PBKDF2, HKDF, HMAC, AES-256-GCM, SHA256, CSPRNG
src/frame.*      — ramka SVP + trailer HMAC
src/tls.*        — transport TCP + TLS 1.3 (na bazie przykładu tls_client.c z PUS-04)
src/vault.*      — sejf w RAM: CRUD, szyfrowanie, scalanie konfliktów
src/client.*     — maszyna stanów protokołu (login/register/get/put/refresh)
src/main.cpp     — CLI / REPL, getpass, lokalny cache
PROTOCOL.md      — kontrakt binarny ramki (wspólny z serwerem)
test/stub_server.py — serwer-zaślepka do testów end-to-end (NIE docelowy serwer)
```

## Test end-to-end (z zaślepką)

```bash
# w jednym terminalu:
cd test && openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem \
           -days 365 -subj "/CN=localhost"
python3 stub_server.py 7443

# w drugim:
./secvault --host 127.0.0.1 --port 7443 --insecure
```
