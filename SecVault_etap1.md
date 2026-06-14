# SecVault Protocol
### Specyfikacja techniczna autorskiego protokołu sieciowego

---

## 1. Cel protokołu i zakres

### 1.1 Do czego służy protokół?

SecVault Protocol (SVP) jest autorskim protokołem warstwy aplikacyjnej przeznaczonym do bezpiecznej synchronizacji zaszyfrowanego sejfu haseł i tajnych danych między klientem (aplikacja desktopowa lub mobilna) a centralnym serwerem przechowalniczym. Protokół umożliwia wielu klientom jednego użytkownika utrzymanie spójnego, aktualnego sejfu — analogicznie do produktów klasy Bitwarden czy 1Password, lecz z własnym protokołem komunikacji zamiast REST/HTTP.

### 1.2 Jakie problemy rozwiązuje?

- **Poufność tajnych danych** — wpisy sejfu są szyfrowane po stronie klienta (AES-256-GCM); serwer przechowuje wyłącznie zaszyfrowane bloki i nigdy nie poznaje klucza głównego.
- **Integralność synchronizacji** — protokół wykrywa konflikty wersji, duplikaty i częściowe transfery.
- **Uwierzytelnienie bez ujawniania hasła** — hasło główne nie jest przesyłane w żadnej postaci; stosowana jest kryptograficzna odpowiedź na wyzwanie (challenge-response z PBKDF2).
- **Ochrona sesji** — sesja jest chroniona tokenem z ograniczonym czasem życia oraz nonce zapobiegającym atakom replay.
- **Niezawodność połączenia** — obsługa timeoutów, fragmentacji, utraty połączenia i automatycznego wznawiania sesji.

### 1.3 Model działania

Protokół działa w modelu **client–server**. Serwer jest jednostką centralną przechowującą zaszyfrowane sejfy. Klient inicjuje każde połączenie. Wiele klientów może obsługiwać konto jednego użytkownika sekwencyjnie; serwer zapewnia kontrolę wersji sejfu (optimistic locking).

---

## 2. Założenia techniczne

### 2.1 Warstwa transportowa

SVP używa protokołu **TCP** jako warstwy transportowej, port domyślny **7443**. Każde połączenie TCP jest obligatoryjnie owijane warstwą **TLS 1.3** (RFC 8446). Wersje TLS starsze niż 1.2 są odrzucane.

Wymagane cipher suites:
- `TLS_AES_256_GCM_SHA384`
- `TLS_CHACHA20_POLY1305_SHA256`

Certyfikat serwera jest weryfikowany przez klienta; certificate pinning jest opcjonalny (zalecany w produkcji).

### 2.2 Kodowanie komunikatów

Komunikaty mają format **binarny** oparty na stałym nagłówku 11 bajtów oraz zmiennej długości polu danych (little-endian, unsigned integers). Kodowanie binarne wybrano ze względu na mniejszy narzut, czytelne granice ramek (length-prefix framing) i odporność na problemy z escapingiem znaków specjalnych.

### 2.3 Niezawodność — podział odpowiedzialności

| Właściwość | Zapewnia | Uwagi |
|---|---|---|
| Dostarczenie | TCP | Gwarantowane przez warstwę transportową |
| Kolejność | TCP | Zachowanie kolejności ramek |
| Integralność ramki | HMAC-SHA256 (SVP) | Każda wiadomość SVP zawiera HMAC |
| Wykrywanie duplikatów | SVP (SEQ_ID) | Numer sekwencyjny w nagłówku |
| Obsługa fragmentacji | SVP (flaga FRAG) | Duże dane dzielone na fragmenty |
| Keep-alive | SVP (PING/PONG) | Co 30 s; timeout po 3 nieodebranych |
| Retry po utracie sesji | SVP (token refresh) | Token ważny 24h; re-AUTH bez hasła |

---

## 3. Struktura komunikatów

### 3.1 Format ramki

Każda ramka SVP ma następującą strukturę:

```
 Offset  Rozmiar  Pole          Opis
 ------  -------  -----------   ------------------------------------------
   0       1 B    VERSION        Wersja protokołu (aktualnie 0x01)
   1       1 B    MSG_TYPE       Typ wiadomości (patrz sekcja 3.2)
   2       1 B    FLAGS          Flagi bitowe (patrz sekcja 3.3)
   3       4 B    SEQ_ID         Numer sekwencyjny (uint32, per-session, monotonicznie rosnący)
   7       4 B    PAYLOAD_LEN    Długość pola PAYLOAD w bajtach (uint32, max 1 048 576)
  11       N B    PAYLOAD        Dane właściwe (zależne od MSG_TYPE)
 11+N     32 B    HMAC           HMAC-SHA256(nagłówek 11B + PAYLOAD)

 Minimalna ramka (puste PAYLOAD): 43 bajty
 Maksymalny rozmiar ramki:        11 + 1 048 576 + 32 = 1 048 619 bajtów
```

### 3.2 Typy wiadomości

| Kod | Nazwa | Kierunek | Opis |
|---|---|---|---|
| 0x01 | HELLO | C→S | Inicjacja sesji; wersja, client_id, nonce_c |
| 0x02 | CHALLENGE | S→C | Wyzwanie auth; nonce_s, server_id, timestamp |
| 0x03 | AUTH | C→S | Odpowiedź auth; username, hmac_response, totp_code (opcjonalnie) |
| 0x04 | AUTH_OK | S→C | Sukces auth; session_token, expiry, vault_version |
| 0x05 | AUTH_FAIL | S→C | Niepowodzenie auth; error_code, retry_after |
| 0x10 | VAULT_GET | C→S | Żądanie sejfu; vault_id, known_version |
| 0x11 | VAULT_PUT | C→S | Wysłanie zaszyfrowanego sejfu; vault_id, base_version, blob |
| 0x12 | VAULT_SYNC | C→S | Sync różnicowy; vault_id, base_version, delta |
| 0x13 | VAULT_DATA | S→C | Odpowiedź z danymi sejfu; vault_id, version, blob |
| 0x14 | VAULT_ACK | S→C | Potwierdzenie zapisu; vault_id, new_version |
| 0x20 | PING | C↔S | Keep-alive; timestamp |
| 0x21 | PONG | C↔S | Odpowiedź keep-alive; echo timestamp |
| 0xF0 | BYE | C↔S | Grzeczne zamknięcie sesji; reason_code |
| 0xFF | ERROR | S→C | Błąd protokołu/serwera; error_code, message |

### 3.3 Flagi bitowe (FLAGS byte)

| Bit | Nazwa | Znaczenie |
|---|---|---|
| 0 (LSB) | COMPRESSED | Payload skompresowane (zlib deflate) |
| 1 | ENCRYPTED | Dodatkowe szyfrowanie payload ponad TLS (tryb zero-knowledge) |
| 2 | FRAGMENTED | Wiadomość jest fragmentem większej całości |
| 3 | LAST_FRAG | Ostatni fragment serii (używane razem z bitem 2) |
| 4–7 | RESERVED | Zarezerwowane; muszą być 0x00 — nieznane flagi → ERR_BAD_FLAGS |

### 3.4 Pola PAYLOAD dla kluczowych typów

**HELLO (0x01):**

```
 Pole          Typ       Rozmiar  Opis
 ----------    ------    -------  ------------------------------------------
 proto_ver     uint8       1 B    Wersja SVP (0x01)
 client_id     bytes      16 B    UUID v4 klienta (stały dla urządzenia)
 nonce_c       bytes      32 B    Losowy nonce klienta (CSPRNG)
 timestamp     int64       8 B    Unix timestamp UTC w ms
 client_ver    uint16      2 B    Wersja aplikacji klienckiej
 RAZEM                   59 B
```

**AUTH (0x03):**

```
 Pole          Typ       Rozmiar  Opis
 ----------    ------    -------  ------------------------------------------
 user_len      uint8       1 B    Długość pola username (max 64)
 username      utf8      1–64 B   Login użytkownika
 hmac_resp     bytes      32 B    HMAC-SHA256 challenge response
 token_refresh uint8       1 B    0x00 = normalny AUTH, 0x01 = refresh tokenem
 session_token bytes       0/N B  Obecny tylko gdy token_refresh=0x01
 totp_present  uint8       1 B    0x00 brak TOTP, 0x01 TOTP załączony
 totp_code     uint32      4 B    Kod TOTP (tylko gdy totp_present=0x01)
```

**VAULT_PUT (0x11):**

```
 Pole          Typ       Rozmiar  Opis
 ----------    ------    -------  ------------------------------------------
 vault_id      bytes      16 B    UUID sejfu
 base_version  uint64      8 B    Wersja od której wychodzimy (CAS check)
 blob_len      uint32      4 B    Rozmiar zaszyfrowanego bloba
 blob          bytes       N B    Zaszyfrowany blob AES-256-GCM:
                                  [GCM_IV:12B || ciphertext || GCM_TAG:16B]
```

**AUTH_OK (0x04):**

```
 Pole          Typ       Rozmiar  Opis
 ----------    ------    -------  ------------------------------------------
 token_len     uint16      2 B    Długość session_token
 session_token bytes       N B    Token sesyjny (patrz sekcja 5.5)
 expiry        int64       8 B    Unix timestamp wygaśnięcia (UTC ms)
 vault_version uint64      8 B    Aktualna wersja sejfu na serwerze
```

### 3.5 Walidacja — co jest błędem formatu

- `VERSION ≠ 0x01` → `ERROR(ERR_BAD_VERSION)`, zamknięcie połączenia
- Nieznany `MSG_TYPE` → `ERROR(ERR_UNKNOWN_TYPE)`
- `PAYLOAD_LEN > 1 048 576` → `ERROR(ERR_TOO_LARGE)`, zamknięcie połączenia
- `FLAGS` z ustawionymi bitami 4–7 → `ERROR(ERR_BAD_FLAGS)`
- Niezgodny HMAC (ostatnie 32 B) → natychmiastowy TCP RST bez odpowiedzi (by nie potwierdzać informacji atakującemu)
- `SEQ_ID` niższy lub równy ostatniemu odebranemu → duplikat, cicho odrzucony
- `FRAGMENTED=1, LAST_FRAG=1`, ale brakuje poprzednich fragmentów → `ERROR(ERR_BAD_SEQ)`
- `timestamp` w HELLO odbiega o więcej niż ±5 min od czasu serwera → `ERROR(ERR_CLOCK_SKEW)`

---

## 4. Model stanów i przebieg komunikacji

### 4.1 Stany sesji klienta

| Stan | Opis | Dozwolone przejścia |
|---|---|---|
| DISCONNECTED | Brak połączenia TCP/TLS | → CONNECTING |
| CONNECTING | Trwa handshake TCP+TLS | → GREETING / DISCONNECTED |
| GREETING | Wysłano HELLO, czekamy na CHALLENGE | → AUTHENTICATING / ERROR |
| AUTHENTICATING | Wysłano AUTH, czekamy na AUTH_OK | → ESTABLISHED / DISCONNECTED |
| ESTABLISHED | Sesja aktywna; wymiana VAULT_* i PING | → CLOSING / DISCONNECTED |
| CLOSING | Wysłano BYE, oczekiwanie na potwierdzenie | → DISCONNECTED |
| ERROR | Błąd nieodwracalny, sesja zepsuta | → DISCONNECTED |

### 4.2 Diagram sekwencji — poprawna sesja

```
 Klient                                          Serwer
   |                                               |
   |── TCP connect ─────────────────────────────>  |
   |<─────────────────────── TCP accept ───────────|
   |                                               |
   |══════════════ TLS 1.3 Handshake ══════════════|
   |                                               |
   |── HELLO(ver=1, client_id, nonce_c, ts) ─────> |  [GREETING]
   |<── CHALLENGE(nonce_s, ts_server) ─────────────|  [AUTHENTICATING]
   |                                               |
   |  K_auth    = PBKDF2(password, SHA256(user), 200000, 32)
   |  hmac_resp = HMAC-SHA256(nonce_c || nonce_s || username, K_auth)
   |                                               |
   |── AUTH(username, hmac_resp, totp?) ─────────> |
   |<── AUTH_OK(session_token, expiry, vault_ver) ─|  [ESTABLISHED]
   |                                               |
   |── VAULT_GET(vault_id, known_version=0) ──────>|
   |<── VAULT_DATA(vault_id, version=42, blob) ────|
   |                                               |
   |  [klient deszyfruje blob kluczem pochodnym master_password]
   |                                               |
   |── PING(ts) ──────────────────────────────── > |  (co 30 s)
   |<── PONG(ts) ───────────────────────────────── |
   |                                               |
   |── BYE(reason=0x00 NORMAL) ─────────────────>  |  [CLOSING]
   |<── BYE(reason=0x00) ───────────────────────── |
   |── TCP FIN ──────────────────────────────────> |  [DISCONNECTED]
   |                                               |
```

### 4.3 Timeouty, retry i keep-alive

| Parametr | Wartość | Zachowanie po przekroczeniu |
|---|---|---|
| TLS handshake timeout | 10 s | TCP RST, powrót do DISCONNECTED |
| HELLO→CHALLENGE timeout | 5 s | Zamknięcie, retry z backoff |
| AUTH→AUTH_OK timeout | 10 s | Zamknięcie; ERR_TIMEOUT |
| Keep-alive PING interval | 30 s | Wysłanie PING; oczekiwanie na PONG |
| PONG timeout | 10 s | Rozłączenie; jeśli token ważny → re-HELLO |
| Idle session timeout | 15 min | Serwer wysyła BYE(IDLE_TIMEOUT) |
| Session token lifetime | 24 h | Token refresh; klient musi ponownie AUTH |
| Reconnect backoff | exp(k×2^n), max 60 s | Jitter ±10% celem unikania connection storm |

---

## 5. Bezpieczeństwo

### 5.1 Poufność — TLS 1.3

Cały ruch SVP jest owijany warstwą TLS 1.3. Żadna ramka SVP nie jest transmitowana przez gołe TCP. Wymagane są wyłącznie cipher suites AEAD (brak CBC). Serwer musi posiadać certyfikat X.509 podpisany przez zaufane CA.

Ponadto dane sejfu są szyfrowane **po stronie klienta** kluczem pochodnym hasła głównego (AES-256-GCM). Nawet jeśli TLS zostanie skompromitowany lub serwer zostanie przejęty, wpisy sejfu pozostają zaszyfrowane — model **zero-knowledge**.

### 5.2 Integralność — HMAC-SHA256

Każda ramka SVP jest chroniona 32-bajtowym HMAC-SHA256. Klucz HMAC jest pochodną tokena sesyjnego i nonce klienta:

```
K_mac = HKDF-SHA256(session_token, salt=nonce_c, info='svp-mac', length=32)
```

Niezgodność HMAC powoduje natychmiastowe TCP RST bez wysyłania odpowiedzi (by nie ujawniać informacji atakującemu). Porównanie wykonywane jest metodą **constant-time** (`hmac.compare_digest`), co eliminuje timing attacks.

### 5.3 Uwierzytelnienie — challenge-response bez przesyłania hasła

Hasło główne użytkownika **nigdy nie jest przesyłane** — ani wprost, ani w zaszyfrowanej formie.

```
1. Klient oblicza klucz autentykacji:
   K_auth = PBKDF2-HMAC-SHA256(
       password  = master_password,
       salt      = SHA256(username),
       iterations= 200 000,
       length    = 32
   )

2. Serwer wysyła CHALLENGE z losowym nonce_s i timestampem.

3. Klient oblicza odpowiedź:
   hmac_resp = HMAC-SHA256(nonce_c || nonce_s || username, K_auth)

4. Serwer weryfikuje hmac_resp porównując z wartością obliczoną lokalnie.
   Serwer przechowuje K_auth w bazie (nie master_password).

5. Opcjonalnie: klient dołącza 6-cyfrowy kod TOTP (RFC 6238, SHA-1, 30 s).
```

### 5.4 Autoryzacja

Po pomyślnej autentykacji serwer przyznaje dostęp wyłącznie do vaultów przypisanych do danego `user_id`. Próba odczytu cudzego `vault_id` zwraca `ERROR(ERR_FORBIDDEN)` z odpowiedzią identyczną jak `ERR_NOT_FOUND` — bez ujawniania, czy zasób istnieje.

### 5.5 Ochrona przed replay — nonce + SEQ_ID + timestamp

- **nonce_c** (32 B, CSPRNG) — unikalny per sesję; uniemożliwia odtworzenie HELLO
- **nonce_s** (32 B, CSPRNG) — generowany przez serwer per każdy CHALLENGE; uniemożliwia odtworzenie AUTH
- **timestamp w HELLO** — serwer odrzuca żądania z rozbieżnością > ±5 min (`ERR_CLOCK_SKEW`)
- **SEQ_ID** (uint32, monotonicznie rosnący) — ramki z SEQ_ID ≤ ostatniemu są cicho odrzucane; okno śledzenia: 1024 ostatnich SEQ_ID
- **session_token** — format `header.payload.sig`; zawiera `issued_at`, `expires_at`, `session_uuid`; podpisany `HMAC-SHA256(header||payload, K_srv)`; ważny 24h

### 5.6 Model zagrożeń

| Zagrożenie | Mechanizm ochrony |
|---|---|
| Podsłuch (eavesdropping) | TLS 1.3 + szyfrowanie payload po stronie klienta (AES-256-GCM) |
| Man-in-the-middle | Weryfikacja certyfikatu X.509; opcjonalny cert pinning |
| Kradzież hasła przez sniffing | Hasło nigdy nie jest wysyłane (challenge-response + PBKDF2) |
| Replay attack | nonce_c, nonce_s, timestamp, SEQ_ID, krótki TTL tokena |
| Brute-force logowania | Rate limit: 5 prób / 15 min / IP; blokada wykładnicza |
| Przejęcie sesji (token theft) | Token ważny 24h; binding do client_id |
| Wyciek danych serwera | Zero-knowledge: serwer widzi tylko szyfrogramy AES-GCM |
| DoS przez wielkie wiadomości | PAYLOAD_LEN max 1 MB; limit połączeń per IP |
| Podrobienie wiadomości | HMAC-SHA256 każdej ramki; klucz pochodny z session_token |
| Timing attack na HMAC | Porównanie constant-time (`hmac.compare_digest`) |

---

## 6. Obsługa błędów i awarii połączenia

### 6.1 Kody błędów

| Kod (hex) | Nazwa | Znaczenie i zachowanie |
|---|---|---|
| 0x01 | ERR_BAD_VERSION | Nieznana wersja protokołu → BYE + rozłącz |
| 0x02 | ERR_BAD_FORMAT | Błąd parsowania nagłówka/payload → BYE + rozłącz |
| 0x03 | ERR_BAD_HMAC | Niezgodny HMAC → natychmiastowe TCP RST (bez odpowiedzi) |
| 0x04 | ERR_BAD_FLAGS | Nieprawidłowe flagi → ERROR, sesja może trwać |
| 0x05 | ERR_UNKNOWN_TYPE | Nieznany MSG_TYPE → ERROR, sesja może trwać |
| 0x06 | ERR_AUTH_FAILED | Błędne dane uwierzytelnienia → AUTH_FAIL(retry_after) |
| 0x07 | ERR_SESSION_EXPIRED | Token wygasł → klient musi ponownie AUTH |
| 0x08 | ERR_NOT_FOUND | Żądany vault_id nie istnieje |
| 0x09 | ERR_FORBIDDEN | Brak dostępu (odpowiedź identyczna z NOT_FOUND) |
| 0x0A | ERR_CONFLICT | Konflikt wersji sejfu — base_version niezgodna |
| 0x0B | ERR_TOO_LARGE | Przekroczono max rozmiar wiadomości |
| 0x0C | ERR_RATE_LIMITED | Przekroczono limit żądań; pole retry_after w sekundach |
| 0x0D | ERR_TIMEOUT | Brak odpowiedzi w oczekiwanym czasie |
| 0x0E | ERR_CLOCK_SKEW | Timestamp odbiega o więcej niż ±5 min |
| 0x0F | ERR_BAD_SEQ | Błąd sekwencji fragmentów |
| 0xFF | ERR_INTERNAL | Wewnętrzny błąd serwera; klient może ponowić po chwili |

### 6.2 Zachowanie po błędach składni/protokołu

Błędy **nieodwracalne** (`ERR_BAD_VERSION`, `ERR_BAD_FORMAT`, `ERR_BAD_HMAC`) powodują natychmiastowe zamknięcie połączenia TCP.

Błędy **łagodne** (`ERR_UNKNOWN_TYPE`, `ERR_BAD_FLAGS`, `ERR_TOO_LARGE`) skutkują wysłaniem ramki ERROR i odrzuceniem pojedynczej ramki — sesja pozostaje aktywna. Po 3 błędach łagodnych w ciągu 60 s serwer eskaluje do zamknięcia sesji.

### 6.3 Timeout i utrata połączenia

- Jeżeli TCP jest zerwane (RST/EOF): klient przechodzi do stanu DISCONNECTED i próbuje ponownie połączyć się po czasie backoff `exp(1×2^n s)`, max 60 s, jitter ±10%.
- Jeśli `session_token` jest wciąż ważny (< 24h): klient wysyła nowe HELLO → AUTH z polem `token_refresh=0x01`, omijając podanie `hmac_resp` — serwer weryfikuje token i wydaje odświeżony AUTH_OK.
- Keep-alive: jeżeli serwer nie odbierze PING przez 90 s (3 × 30 s), uznaje sesję za martwą i zwalnia zasoby.

### 6.4 Duplikaty i niekompletne wiadomości

- **Duplikaty:** ramki z `SEQ_ID ≤ max_seen_seq` są cicho odrzucane. Okno śledzenia: 1024 ostatnich `SEQ_ID`.
- **Niekompletne fragmenty:** jeśli klient znika w trakcie serii `FRAGMENTED=1`, serwer po 30 s odrzuca niekompletny zbiór i zwalnia bufor — po wznowieniu klient wysyła całość od nowa.
- **Częściowe dane TCP:** warstwa SVP czeka na dokładnie `PAYLOAD_LEN` bajtów; jeśli TCP zamknie się wcześniej, ramka jest odrzucana bez ERROR.

### 6.5 Limity i ochrona przed nadużyciami

| Limit | Wartość | Reakcja |
|---|---|---|
| Max rozmiar ramki | 1 MB payload (1 048 619 B total) | ERR_TOO_LARGE, BYE |
| Max połączeń per IP | 10 jednoczesnych | TCP reject |
| Max prób auth / 15 min / IP | 5 | ERR_RATE_LIMITED, lockout |
| Max żądań VAULT_* / min | 60 | ERR_RATE_LIMITED + retry_after |
| Max rozmiar sejfu | 50 MB (skompresowany blob) | ERR_TOO_LARGE |
| Max długość username | 64 bajty UTF-8 | ERR_BAD_FORMAT |
| Błędy łagodne / 60 s | 3 | Eskalacja do zamknięcia sesji |

---

## 7. Przykładowe scenariusze komunikacji

### 7.1 Scenariusz 1 — poprawne połączenie i synchronizacja sejfu

Użytkownik `alice` loguje się z nowego urządzenia i pobiera swój sejf.

```
[TCP + TLS 1.3 Handshake zakończony pomyślnie]

C→S  HELLO  ver=0x01  client_id=a1b2c3d4...  nonce_c=<32B random>  ts=1700000000000
S→C  CHALLENGE  nonce_s=<32B random>  ts_server=1700000000012

[Klient oblicza:]
  K_auth    = PBKDF2-HMAC-SHA256("master_pass", SHA256("alice"), 200000, 32)
  hmac_resp = HMAC-SHA256(nonce_c || nonce_s || "alice", K_auth)

C→S  AUTH  user="alice"  hmac_resp=<32B>  token_refresh=0x00  totp_present=0x00
S→C  AUTH_OK  session_token=<token>  expiry=T+24h  vault_version=42

C→S  VAULT_GET  vault_id=<UUID>  known_version=0
S→C  VAULT_DATA  vault_id=<UUID>  version=42  blob=<zaszyfrowany AES-256-GCM>

[Klient deszyfruje blob kluczem pochodnym master_password — serwer blob nie widział]

C→S  PING  ts=1700000030000
S→C  PONG  ts=1700000030000

C→S  BYE  reason=0x00
S→C  BYE  reason=0x00
[TCP FIN]
```

### 7.2 Scenariusz 2 — błąd autentykacji i rate-limiting

Atakujący próbuje zgadnąć hasło użytkownika `bob`.

```
[TLS Handshake OK]

C→S  HELLO  client_id=<UUID>  nonce_c=<32B>  ts=1700001000000
S→C  CHALLENGE  nonce_s=<32B>  ts_server=1700001000005
C→S  AUTH  user="bob"  hmac_resp=<błędna wartość>
S→C  AUTH_FAIL  error=0x06(ERR_AUTH_FAILED)  retry_after=0        [próba 1/5]

C→S  HELLO  (nowy nonce_c)
S→C  CHALLENGE  nonce_s=<nowy>
C→S  AUTH  user="bob"  hmac_resp=<błędna wartość>
S→C  AUTH_FAIL  error=0x06  retry_after=0                         [próba 2/5]

... (próby 3, 4, 5 analogicznie) ...

C→S  HELLO  (szósta próba w ciągu 15 min)
S→C  AUTH_FAIL  error=0x0C(ERR_RATE_LIMITED)  retry_after=900
                [IP zablokowane na 15 minut]
[Serwer zamyka TCP]
```

### 7.3 Scenariusz 3 — konflikt wersji sejfu (optimistic locking)

Użytkownik `alice` modyfikuje sejf jednocześnie na dwóch urządzeniach.

```
[Urządzenie A: pobiera vault_version=42, modyfikuje lokalnie]

Dev-A→S  VAULT_PUT  vault_id=<UUID>  base_version=42  blob=<encrypted_A>
S→Dev-A  VAULT_ACK  vault_id=<UUID>  new_version=43

[Urządzenie B: ma w pamięci podręcznej vault_version=42, nie wie o zmianie A]

Dev-B→S  VAULT_PUT  vault_id=<UUID>  base_version=42  blob=<encrypted_B>
S→Dev-B  ERROR  error=0x0A(ERR_CONFLICT)  [bieżąca wersja serwera: 43]

[Urządzenie B musi pobrać aktualną wersję i scalić zmiany lokalnie]

Dev-B→S  VAULT_GET  vault_id=<UUID>  known_version=43
S→Dev-B  VAULT_DATA  vault_id=<UUID>  version=43  blob=<encrypted_A>

[Dev-B scala zmiany (merge po stronie klienta) → merged_blob]

Dev-B→S  VAULT_PUT  vault_id=<UUID>  base_version=43  blob=<merged_blob>
S→Dev-B  VAULT_ACK  vault_id=<UUID>  new_version=44
```

### 7.4 Scenariusz 4 — utrata połączenia i automatyczne wznowienie

Klient traci połączenie w trakcie fragmentowanej transmisji dużego sejfu.

```
[Sesja aktywna; session_token ważny do T+24h]

C→S  VAULT_PUT  vault_id=<UUID>  base_version=10  blob=<duży>
     FLAGS: FRAGMENTED=1, LAST_FRAG=0  SEQ_ID=55
C→S  [fragment 2/4]  SEQ_ID=56
[TCP zerwane przez sieć — serwer odrzuca niekompletne fragmenty po 30 s]

--- backoff 2 s --- reconnect ---

[Nowy TCP + TLS 1.3 Handshake]

C→S  HELLO  client_id=<ten sam UUID>  nonce_c=<nowy 32B>  ts=...
S→C  CHALLENGE  nonce_s=<nowy>
C→S  AUTH  user="alice"  token_refresh=0x01  session_token=<stary token>
            [brak hmac_resp — klient używa ważnego tokena]
S→C  AUTH_OK  session_token=<odświeżony>  vault_version=10

C→S  VAULT_PUT  vault_id=<UUID>  base_version=10  blob=<duży>
     [tym razem wszystkie 4 fragmenty dostarczone poprawnie]
S→C  VAULT_ACK  vault_id=<UUID>  new_version=11
```

---

## Podsumowanie

SecVault Protocol (SVP v1.0) zapewnia kompletną, bezpieczną warstwę komunikacji dla menedżera haseł w architekturze klient-serwer. Kluczowe właściwości:

- **Zero-knowledge** — dane sejfu szyfrowane po stronie klienta (AES-256-GCM); serwer przechowuje wyłącznie szyfrogramy.
- **Silne uwierzytelnienie** — challenge-response z PBKDF2 (200 000 iteracji); opcjonalne TOTP; hasło główne nigdy nie opuszcza klienta.
- **Wielowarstwowa integralność** — TLS 1.3 na poziomie transportu + HMAC-SHA256 na poziomie każdej ramki SVP.
- **Ochrona przed replay** — nonce_c, nonce_s, timestamp, SEQ_ID, krótkotrwały token sesyjny z UUID.
- **Niezawodność** — obsługa fragmentacji, duplikatów, utraty połączenia, automatycznego wznowienia sesji tokenem, keep-alive.
- **Odporność na nadużycia** — rate-limiting, max rozmiar wiadomości, limit połączeń per IP, backoff wykładniczy z jitterem.