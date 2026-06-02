# SVP v1.0 — kontrakt binarny ramki (do uzgodnienia klient ↔ serwer)

To jest „zamrożony kontrakt" z planu (sekcja 6.2). Klient w `client/` implementuje
dokładnie ten format; serwer musi go odwzorować.

## Ramka

```
+-----------+----------+----------+-----------+--------------+-------------------+-----------------+
| VERSION 1B| TYPE 1B  | FLAGS 1B | SEQ_ID 4B | PAYLOAD_LEN 4| PAYLOAD (N)       | HMAC-SHA256 32B |
+-----------+----------+----------+-----------+--------------+-------------------+-----------------+
        \__________________ nagłówek 11B ___________________/
```

- Kodowanie liczb: **little-endian, unsigned**.
- `VERSION = 0x01`. `PAYLOAD_LEN ≤ 1 MiB` (TS-06 → `ERR_TOO_LARGE`).
- **HMAC trailer** = `HMAC-SHA256(K_mac, nagłówek || PAYLOAD)` (32 B).
  - `K_mac = HKDF-SHA256(IKM = session_token, salt = nonce_c, info = "svp-mac", L = 32)`.
  - **Ramki przed ustaleniem sesji** (HELLO, CHALLENGE, AUTH, AUTH_OK/FAIL, REGISTER,
    REGISTER_OK) nie mają jeszcze `K_mac` → trailer to **32 bajty zerowe**; ich integralność
    i poufność zapewnia TLS 1.3. Pierwszą ramką uwierzytelnianą HMAC-iem jest ta po `AUTH_OK`.
- Transport: TCP + TLS 1.3, port **7443**.

## Typy komunikatów

| Hex  | Nazwa        | Kier. |
|------|--------------|-------|
| 0x01 | HELLO        | C→S   |
| 0x02 | CHALLENGE    | S→C   |
| 0x03 | AUTH         | C→S   |
| 0x04 | AUTH_OK      | S→C   |
| 0x05 | AUTH_FAIL    | S→C   |
| 0x06 | REGISTER     | C→S   |
| 0x07 | REGISTER_OK  | S→C   |
| 0x10 | VAULT_GET    | C→S   |
| 0x11 | VAULT_DATA   | S→C   |
| 0x12 | VAULT_PUT    | C→S   |
| 0x13 | VAULT_ACK    | S→C   |
| 0x14 | VAULT_SYNC   | C→S   |
| 0x20 | PING         | C↔S   |
| 0x21 | PONG         | C↔S   |
| 0x2E | BYE          | C↔S   |
| 0x2F | ERROR        | S→C   |

## Flagi (bitfield)

`0x01 FRAGMENTED`, `0x02 LAST_FRAG`, `0x04 COMPRESSED`, `0x08 TOTP_PRESENT`, `0x10 TOKEN_REFRESH`.

## Kody błędów (`ERROR`/`AUTH_FAIL`)

`0x01 AUTH_FAILED`, `0x02 RATE_LIMITED`, `0x03 CLOCK_SKEW`, `0x04 CONFLICT`, `0x05 NOT_FOUND`,
`0x06 TOO_LARGE`, `0x07 SESSION_EXPIRED`, `0x08 FORBIDDEN`, `0x09 UNKNOWN_TYPE`,
`0x0A BAD_HMAC`, `0xFF INTERNAL`.

## Kodowanie pól w PAYLOAD

- `u8/u16/u32/u64` — little-endian.
- `raw(n)` — n surowych bajtów.
- `lpstr` / `lpbytes` — `u16` długość + bajty (≤ 64 KiB).
- `lpblob` — `u32` długość + bajty (sejf).

### Układy payloadów

| Komunikat   | PAYLOAD |
|-------------|---------|
| HELLO       | `client_id raw(16)` · `nonce_c raw(16)` · `timestamp u64` |
| CHALLENGE   | `nonce_s raw(16)` · `timestamp_s u64` |
| AUTH (pełne)| `login lpstr` · `hmac_resp raw(32)` [· jeśli TOTP_PRESENT: `totp_code lpstr`] |
| AUTH (refresh, flaga TOKEN_REFRESH) | `login lpstr` · `session_token lpbytes` |
| AUTH_OK     | `session_token lpbytes` · `expiry u64` · `vault_id raw(16)` · `vault_version u32` |
| AUTH_FAIL   | `err_code u8` · `retry_after u32` |
| REGISTER    | `login lpstr` · `K_auth raw(32)` |
| REGISTER_OK | `vault_id raw(16)` |
| VAULT_GET   | `vault_id raw(16)` · `known_version u32` |
| VAULT_DATA  | `vault_id raw(16)` · `version u32` · `blob lpblob` |
| VAULT_PUT   | `vault_id raw(16)` · `base_version u32` · `blob lpblob` |
| VAULT_ACK   | `vault_id raw(16)` · `new_version u32` |
| PING / PONG | puste |
| BYE         | `reason u8` |
| ERROR       | `err_code u8` [· `message lpstr`] |

## Kryptografia (po stronie klienta — zero-knowledge)

- `K_auth = PBKDF2-HMAC-SHA256(hasło, salt = SHA256(login), iter = 200000, len = 32)`
  — weryfikator; serwer przechowuje `K_auth`.
- `K_vault = PBKDF2-HMAC-SHA256(hasło, salt = SHA256("secvault-vault:" + login), 200000, 32)`
  — klucz sejfu; **niezależna sól**, więc serwer (znający `K_auth`) nie wyprowadzi `K_vault`.
- `hmac_resp = HMAC-SHA256(K_auth, nonce_c || nonce_s || login)`.
- Sejf: `blob = IV(12B) || AES-256-GCM(K_vault, IV, plaintext) || GCM_TAG(16B)`.
- `session_token` jest nieprzezroczysty dla klienta; serwer go generuje (np.
  `HMAC(SECRET, session_uuid || client_id || expiry)`), a klient używa go jako IKM do `K_mac`.

> Uwaga projektowa: serwer przechowuje `K_auth` jako weryfikator (uproszczenie wobec
> augmented-PAKE). Wyciek bazy ujawnia `K_auth` (umożliwia podszycie), ale **nie** `K_vault`,
> więc zawartość sejfów pozostaje poufna — zgodnie z modelem zero-knowledge.
