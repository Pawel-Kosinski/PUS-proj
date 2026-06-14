# SecVault - serwer (Python)

Asynchroniczny serwer TCP dla projektu SecVault (PUS), implementujacy protokol SVP v1.0.
Serwer dziala w modelu event-loop (`asyncio`) i obsluguje bezpieczna komunikacje przez TLS 1.3.

Zakres odpowiedzialnosci serwera:
- handshake i autoryzacja sesji,
- walidacja i kodowanie binarnych ramek SVP,
- przechowywanie zaszyfrowanych blobow sejfu,
- optimistic locking (CAS) przy zapisie wersji sejfu.

## Zaleznosci

- Python 3.13+ (zalecane: wspolne `.venv` w katalogu glownym)
- `cryptography` (HKDF, wsparcie krypto)
- `aiosqlite` (asynchroniczny dostep do SQLite)
- `pyotp` (opcjonalne 2FA TOTP)
- `pytest`, `pytest-asyncio` (testy)

Przyklad instalacji (z katalogu glownego projektu):

```bash
.venv\Scripts\python.exe -m pip install -r server-py/requirements.txt
```

## Uruchomienie serwera

```bash
cd server-py
python server.py
```

Domyslnie serwer:
- nasluchuje na `0.0.0.0:7443`,
- korzysta z certyfikatu TLS z `certs/server.crt` i klucza `certs/server.key`,
- inicjalizuje baze `secvault.db` przy starcie.

## Transport i bezpieczenstwo TLS 1.3

Implementacja w [server.py](server.py):
- `ssl.PROTOCOL_TLS_SERVER`,
- `minimum_version = TLSv1_3` i `maximum_version = TLSv1_3`,
- cert chain ladowany z lokalnych plikow,
- obsluga klientow przez `asyncio.start_server`.

## Codec binarny SVP i maszyna stanow

Implementacja formatu ramki znajduje sie w [protocol.py](protocol.py):
- naglowek 11B: `VERSION | MSG_TYPE | FLAGS | SEQ_ID | PAYLOAD_LEN`,
- little-endian (`<BBBII`),
- HMAC-SHA256 (32B trailer),
- walidacja reserved bits i HMAC (`hmac.compare_digest`).

Maszyna stanow sesji jest w [server.py](server.py):
- `GREETING` -> `AUTHENTICATING` -> `ESTABLISHED`,
- pre-auth z kluczem dummy, po AUTH klucz sesyjny z HKDF,
- obsluga `PING/PONG`, `BYE`, timeout idle i timeout fragmentacji.

## Baza danych SQLite (`aiosqlite`) i CAS

Warstwa DB jest zaimplementowana w [database.py](database.py):
- `users(id, username, k_auth, totp_secret)`,
- `vaults(id, user_id, version, blob, ts)`,
- `sessions(token, user_id, expiry, client_id)`.

Optimistic locking (CAS):
- `VAULT_PUT` przyjmuje `base_version`,
- serwer akceptuje zapis tylko gdy `base_version == current_version`,
- przy konflikcie zwraca `ERR_CONFLICT`.

## Seed testowego uzytkownika `alice`

Uruchom z katalogu glownego projektu:

```powershell
& "C:\Users\05lan\Desktop\PUS-proj\.venv\Scripts\python.exe" -c "import sqlite3,hashlib;db=r'c:\\Users\\05lan\\Desktop\\PUS-proj\\server-py\\secvault.db';u='alice';p='alicepass';k=hashlib.pbkdf2_hmac('sha256',p.encode(),hashlib.sha256(u.encode()).digest(),200000,32);con=sqlite3.connect(db);con.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, k_auth BLOB, totp_secret TEXT NULL)');con.execute('INSERT INTO users(username,k_auth,totp_secret) VALUES(?,?,NULL) ON CONFLICT(username) DO UPDATE SET k_auth=excluded.k_auth, totp_secret=NULL',(u,k));con.commit();con.close();print('Seeded alice')"
```

## Testy

Uruchom wszystkie testy serwera:

```bash
.venv\Scripts\python.exe -m pytest server-py/tests/test_handshake.py server-py/tests/test_vault.py server-py/tests/test_lifecycle.py server-py/tests/test_totp.py -q
```
