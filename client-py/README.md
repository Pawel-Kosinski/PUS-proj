# SecVault - klient (Python)

Klient CLI dla projektu SecVault (PUS), interoperacyjny z serwerem Python z katalogu [../server-py](../server-py).
Komunikacja odbywa sie przez SVP v1.0 (binarne ramki) po TCP z obowiazkowym TLS 1.3.

Kryptografia danych sejfu jest wykonywana po stronie klienta (model zero-knowledge):
serwer przechowuje zaszyfrowane bloby i metadane wersjonowania.

## Zaleznosci

- Python 3.13+ (zalecane: wspolne `.venv` w katalogu glownym projektu)
- `cryptography` (AES-256-GCM, HKDF)
- modul standardowy: `socket`, `ssl`, `hashlib`, `hmac`, `secrets`, `struct`, `getpass`

```bash
pip install -r requirements.txt
```

## Uruchomienie

```bash
python secvault.py --host 127.0.0.1 --port 7443 [--ca ca-cert.pem] [--insecure] \
                   [--cache .svp_cache] [--offline] [--debug]

python secvault.py --selftest
```

- `--insecure` - wylacza weryfikacje certyfikatu (lokalne testy z cert self-signed).
- `--ca plik.pem` - weryfikacja certyfikatu serwera przez wskazane CA.
- `--offline` - praca na lokalnej zaszyfrowanej kopii (`.svp_cache`).
- `--debug` - metadane ramek SVP na stderr.

Po starcie klient uruchamia REPL:

```text
ls · get <serwis|id> · add · edit <serwis|id> · rm <serwis|id>
sync · pull · ping · help · quit
```

## Architektura klienta

| Modul | Rola |
|---|---|
| `protocol.py` | stale SVP (typy wiadomosci, flagi, limity, kody bledow) |
| `framing.py` | `ByteWriter`/`ByteReader`, serializacja i parse ramek 11B + HMAC |
| `transport.py` | TCP + TLS 1.3 (`ssl.create_default_context`, `wrap_socket`) |
| `svpcrypto.py` | PBKDF2/HMAC/SHA256 + AES-256-GCM + HKDF |
| `svpclient.py` | maszyna stanow klienta (HELLO/AUTH, refresh, VAULT_GET/PUT, PING/BYE) |
| `vault.py` | model sejfu w RAM, CRUD, (de)szyfrowanie, merge konfliktow |
| `secvault.py` | CLI/REPL i orchestration flow |

## Obslugiwane scenariusze

- Logowanie challenge-response (z opcjonalnym TOTP).
- Wznowienie sesji tokenem (refresh AUTH).
- Pobieranie i zapis sejfu z optimistic locking (CAS).
- Obsluga konfliktu wersji (merge po stronie klienta).
- Keep-alive PING/PONG i zamkniecie BYE.

## Manual E2E Tutorial (2 terminale)

### 1. Uruchom serwer (Terminal 1)

```powershell
cd C:\Users\05lan\Desktop\PUS-proj\server-py
& "C:\Users\05lan\Desktop\PUS-proj\.venv\Scripts\python.exe" server.py
```

### 2. Uruchom klienta CLI (Terminal 2)

```powershell
cd C:\Users\05lan\Desktop\PUS-proj\client-py
& "C:\Users\05lan\Desktop\PUS-proj\.venv\Scripts\python.exe" secvault.py --host 127.0.0.1 --port 7443 --insecure
```

### 3. Wykonaj pelna sesje uzytkownika

W promptach logowania wpisz:

```text
Uzytkownik: alice
Haslo glowne: alicepass
Zaloguj (l) czy zarejestruj nowe konto (r)? [l]
l
```

Nastepnie w REPL wykonaj:

```text
add
github.com
alice
pass123
manual-e2e

sync
pull
ping
ls
quit
```

### 4. Zatrzymaj serwer

W Terminalu 1 nacisnij `Ctrl+C`.

## Uwagi

- Jesli logowanie `alice` nie przechodzi, zseeduj uzytkownika zgodnie z instrukcja w [../server-py/README.md](../server-py/README.md).
- `--insecure` sluzy tylko do lokalnych testow developerskich.
