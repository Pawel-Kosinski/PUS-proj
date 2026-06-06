# SecVault — klient (Python)

Port klienta CLI z C++ na Pythona. Mówi tym samym protokołem **SVP v1.0** (TCP + TLS 1.3)
i jest **zgodny na poziomie bajtów** z wersją C++ oraz [../client/PROTOCOL.md](../client/PROTOCOL.md)
— sejf zaszyfrowany jednym klientem odszyfruje drugi (zweryfikowane w obie strony).

Cała kryptografia działa po stronie klienta (zero-knowledge): serwer nie poznaje hasła
głównego ani odszyfrowanej zawartości sejfu.

## Zależności

- Python 3.8+
- pakiet [`cryptography`](https://pypi.org/project/cryptography/) (AES-256-GCM, HKDF)
- moduły standardowe: `socket`, `ssl`, `hashlib`, `hmac`, `secrets`, `struct`, `getpass`

```bash
pip install -r requirements.txt
```

## Uruchomienie

```bash
python3 secvault.py --host 127.0.0.1 --port 7443 [--ca ca-cert.pem] [--insecure] \
                    [--cache .svp_cache] [--offline] [--debug]

python3 secvault.py --selftest      # self-test kryptografii (KAT + roundtrip, bez serwera)
```

- `--insecure` — wyłącza weryfikację certyfikatu (cert self-signed / laboratorium).
- `--ca plik.pem` — CA do weryfikacji certyfikatu serwera.
- `--offline` — praca na lokalnej, zaszyfrowanej kopii sejfu (tylko odczyt).
- `--debug` — metadane ramek SVP (tx/rx) na stderr.

Po starcie: nazwa użytkownika + hasło główne (bez echa), następnie REPL:

```
ls · get <serwis|id> · add · edit <serwis|id> · rm <serwis|id>
sync · pull · ping · help · quit
```

## Mapowanie modułów (C++ → Python)

| C++ (`client/src/`) | Python (`client-py/`) | Zawartość |
|---|---|---|
| `protocol.h` | `protocol.py` | stałe SVP: typy, flagi, kody błędów, parametry krypto |
| `crypto.*` | `svpcrypto.py` | PBKDF2/HMAC/SHA256 (stdlib) + AES-256-GCM/HKDF (`cryptography`) |
| `bytes.h` + `frame.*` | `framing.py` | `ByteWriter`/`ByteReader`, `Frame`, serializacja + trailer HMAC |
| `tls.*` | `transport.py` | gniazdo TCP + TLS 1.3 (`socket` + `ssl`), całe ramki SVP |
| `vault.*` | `vault.py` | sejf w RAM: CRUD, szyfrowanie, scalanie konfliktów |
| `client.*` | `svpclient.py` | maszyna stanów: login/register/get/put/refresh |
| `main.cpp` | `secvault.py` | CLI / REPL, getpass, lokalny cache, self-test |

Styl gniazd i TLS wzorowany na przykładach referencyjnych (moduł `socket` + `ssl`,
`create_default_context`, `wrap_socket`).

## Realizowane przypadki użycia

| UC | Opis | Gdzie |
|----|------|-------|
| UC-01 | Logowanie challenge-response (PBKDF2 + HMAC) | `Client.login` |
| UC-02 | Pobranie i deszyfracja sejfu | `Client.fetch_vault`, `Vault.decrypt` |
| UC-03 | Zapis sejfu (optimistic locking, `base_version`) | `Client.put_vault`, `do_sync` |
| UC-04 | Konflikt wersji → scalanie → ponowny PUT | `Vault.merge_from`, `do_sync` |
| UC-05 | Wznowienie sesji tokenem po zerwaniu | `Client.ensure_session` / `refresh_session` |
| UC-06 | TOTP (pole w AUTH) | flaga `FLAG_TOTP_PRESENT` w `Client.login` |
| REGISTER | Rejestracja konta z CLI (rozszerzenie) | `Client.register_account` |

## Test end-to-end (z zaślepką serwera)

Reużywamy stuba z wersji C++ ([../client/test/stub_server.py](../client/test/stub_server.py)) —
działa na poziomie protokołu, więc obsługuje obu klientów.

```bash
# terminal 1 — serwer-zaślepka (TLS 1.3, ten sam protokół):
cd ../client/test && python3 stub_server.py 7443

# terminal 2 — klient Python:
cd client-py && python3 secvault.py --host 127.0.0.1 --port 7443 --insecure
```
