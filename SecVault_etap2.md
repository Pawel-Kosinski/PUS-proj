# SecVault – Etap 2: Projekt aplikacji

**Protokół:** SecVault Protocol (SVP v1.0)  
**Model:** Klient–Serwer  
**Data:** 2025

---

## 1. Opis funkcjonalny aplikacji

### 1.1 Co aplikacja robi?

SecVault to wieloplatformowy menedżer haseł i tajnych danych działający w architekturze klient–serwer. Aplikacja umożliwia użytkownikom bezpieczne przechowywanie, synchronizację i dostęp do zaszyfrowanych sejfów (haseł, notatek, kluczy API, danych kart płatniczych) z dowolnego urządzenia. Dane są szyfrowane **wyłącznie po stronie klienta** (AES-256-GCM) — serwer przechowuje jedynie szyfrogramy i nigdy nie poznaje hasła głównego ani zawartości sejfu (model **zero-knowledge**).

Kluczowe funkcje:

- **Rejestracja i logowanie** — uwierzytelnienie przez challenge-response z PBKDF2, bez przesyłania hasła
- **Opcjonalne 2FA** — kod TOTP (RFC 6238) jako drugi składnik uwierzytelnienia
- **Pobieranie sejfu** — synchronizacja zaszyfrowanego bloba z serwera po zalogowaniu
- **Zapis zmian** — wysłanie zaktualizowanego zaszyfrowanego sejfu z kontrolą wersji (optimistic locking)
- **Synchronizacja różnicowa** — przesyłanie tylko delty zmian (VAULT_SYNC) w celu redukcji transferu danych
- **Rozwiązywanie konfliktów** — wykrywanie równoczesnych edycji z wielu urządzeń i scalanie zmian po stronie klienta
- **Automatyczne wznawianie sesji** — odświeżenie sesji tokenem bez ponownego podawania hasła
- **Zarządzanie wpisami** — lokalne (po deszyfrowaniu) CRUD na hasłach, notatkach, kartach i kluczach

### 1.2 Jaki problem użytkownika rozwiązuje?

| Problem | Rozwiązanie SecVault |
|---|---|
| Słabe, powtarzające się hasła | Menedżer generuje i przechowuje silne, unikalne hasła |
| Brak dostępu do haseł z wielu urządzeń | Szyfrowany sejf synchronizowany przez SVP na wszystkich urządzeniach |
| Zaufanie do dostawcy chmury | Model zero-knowledge — dostawca nie może odczytać danych |
| Ryzyko wycieku przy ataku na serwer | Serwer przechowuje wyłącznie szyfrogramy bez klucza |
| Konflikt zmian przy równoczesnej edycji | Optimistic locking + scalanie po stronie klienta |
| Utrata dostępu przy awarii sieci | Lokalna kopia sejfu; automatyczne wznowienie sesji |

### 1.3 Aktorzy (użytkownicy systemu)

| Aktor | Opis |
|---|---|
| **Użytkownik** | Osoba korzystająca z klienta (desktop/mobilny) w celu zarządzania swoimi hasłami |
| **Serwer SVP** | Centralny serwer przechowujący zaszyfrowane sejfy i weryfikujący sesje |
| **Atakujący (zewnętrzny)** | Podmiot próbujący uzyskać nieautoryzowany dostęp (brute-force, replay, MitM) |
| **Administrator systemu** | Osoba zarządzająca infrastrukturą serwerową (poza zakresem protokołu SVP) |

---

## 2. Architektura rozwiązania

### 2.1 Model: Klient–Serwer

System działa w klasycznym modelu klient–serwer. Serwer jest jednostką centralną, pasywną — odpowiada wyłącznie na żądania klienta. Klient zawsze inicjuje połączenie przez TCP + TLS 1.3 na porcie **7443**. Wielu klientów jednego użytkownika może pracować sekwencyjnie; równoczesna edycja sejfu z dwóch urządzeń jest wykrywana przez mechanizm optimistic locking (pole `base_version`).

### 2.2 Komponenty

```
┌─────────────────────────────────────────────────────────────────┐
│                        KLIENT (Desktop/Mobile)                   │
│                                                                   │
│  ┌──────────────┐   ┌───────────────┐   ┌─────────────────────┐ │
│  │   Warstwa UI  │   │  Moduł krypto │   │  Menedżer protokołu │ │
│  │  (GUI / CLI)  │──▶│  AES-256-GCM  │──▶│  SVP (HELLO/AUTH/  │ │
│  │               │   │  PBKDF2       │   │  VAULT_GET/PUT/SYNC)│ │
│  └──────────────┘   └───────────────┘   └────────┬────────────┘ │
│                                                    │              │
│  ┌──────────────────────────────────────┐          │              │
│  │     Lokalna pamięć podręczna          │◀─────────┘              │
│  │  (sejf odszyfrowany w RAM / plik tmp) │                        │
│  └──────────────────────────────────────┘                        │
└─────────────────────────────────────────────────────────────────┘
                          │  TCP + TLS 1.3 (port 7443)
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                           SERWER SVP                             │
│                                                                   │
│  ┌──────────────────┐   ┌──────────────────┐   ┌─────────────┐  │
│  │  Moduł nasłuchu  │   │  Moduł autoryzacji│   │   Moduł     │  │
│  │  TCP + TLS 1.3   │──▶│  (challenge-resp, │──▶│  sejfów     │  │
│  │  (port 7443)     │   │   token, rate-lim)│   │  (VAULT_*)  │  │
│  └──────────────────┘   └──────────────────┘   └──────┬──────┘  │
│                                                         │         │
│  ┌──────────────────────────────────────────┐           │         │
│  │               Baza danych                 │◀──────────┘         │
│  │  users(id, username, K_auth, totp_secret) │                    │
│  │  vaults(id, user_id, version, blob, ts)   │                    │
│  │  sessions(token, user_id, expiry, client) │                    │
│  └──────────────────────────────────────────┘                    │
│                                                                   │
│  ┌──────────────────────────────────────────┐                    │
│  │           Moduł logowania / diagnostyki   │                    │
│  │  (logi sesji, błędów, rate-limit events)  │                    │
│  └──────────────────────────────────────────┘                    │
└─────────────────────────────────────────────────────────────────┘
```

### 2.3 Diagram komponentów

```
[Klient GUI/CLI]
      │
      │ wywołuje
      ▼
[Menedżer protokołu SVP]──────────────[Moduł krypto]
      │                                      │
      │ ramki SVP przez TLS 1.3              │ klucze pochodne PBKDF2/HKDF
      ▼                                      ▼
[Serwer: Moduł nasłuchu]          [Lokalna pamięć (RAM)]
      │
      ├──▶ [Moduł autoryzacji] ──▶ [Baza: tabela users, sessions]
      │
      └──▶ [Moduł sejfów]      ──▶ [Baza: tabela vaults]
                                         │
                                    [Moduł logowania]
```

### 2.4 Przepływ danych między komponentami

```
LOGOWANIE I POBIERANIE SEJFU:

 Użytkownik wpisuje hasło
        │
        ▼
 Klient oblicza K_auth = PBKDF2(hasło, SHA256(login), 200000, 32)
        │
        ▼
 Klient → Serwer: HELLO (nonce_c, client_id, timestamp)
        │
        ▼
 Serwer → Klient: CHALLENGE (nonce_s, timestamp_serwera)
        │
        ▼
 Klient oblicza hmac_resp = HMAC-SHA256(nonce_c||nonce_s||login, K_auth)
 Klient → Serwer: AUTH (login, hmac_resp, [totp_code])
        │
        ▼
 Serwer weryfikuje hmac_resp z lokalnie obliczoną wartością
 Serwer → Klient: AUTH_OK (session_token, vault_version)
        │
        ▼
 Klient → Serwer: VAULT_GET (vault_id, known_version)
        │
        ▼
 Serwer → Klient: VAULT_DATA (version, blob_zaszyfrowany)
        │
        ▼
 Klient deszyfruje blob kluczem pochodnym hasła (AES-256-GCM)
 Wpisy sejfu dostępne w pamięci RAM klienta

ZAPIS ZMIAN:

 Użytkownik modyfikuje wpis
        │
        ▼
 Klient szyfruje całość sejfu nowym IV (AES-256-GCM)
        │
        ▼
 Klient → Serwer: VAULT_PUT (vault_id, base_version, blob)
        │
        ▼ [jeśli base_version == aktualna wersja na serwerze]
 Serwer zapisuje blob, inkrementuje wersję
 Serwer → Klient: VAULT_ACK (vault_id, new_version)
        │
        ▼ [jeśli base_version != aktualna wersja → konflikt]
 Serwer → Klient: ERROR(ERR_CONFLICT)
 Klient pobiera aktualny sejf, scala lokalnie, ponawia VAULT_PUT
```

---

## 3. Przypadki użycia

### UC-01: Logowanie użytkownika

| Pole | Opis |
|---|---|
| **Cel** | Uwierzytelnienie użytkownika i uzyskanie aktywnej sesji SVP |
| **Aktor** | Użytkownik |
| **Warunki wstępne** | Konto istnieje na serwerze; klient ma dostęp do sieci; zegary klienta i serwera różnią się o mniej niż ±5 min |
| **Scenariusz główny** | 1. Użytkownik wpisuje login i hasło główne w aplikacji klienckiej.<br>2. Klient nawiązuje połączenie TCP + TLS 1.3 z serwerem na porcie 7443.<br>3. Klient wysyła `HELLO` (nonce_c, client_id, timestamp).<br>4. Serwer odsyła `CHALLENGE` (nonce_s, timestamp_serwera).<br>5. Klient oblicza `K_auth = PBKDF2(hasło, SHA256(login), 200000, 32)` i `hmac_resp = HMAC-SHA256(nonce_c‖nonce_s‖login, K_auth)`.<br>6. Klient wysyła `AUTH` (login, hmac_resp).<br>7. Serwer weryfikuje hmac_resp metodą constant-time; jeśli poprawny — odsyła `AUTH_OK` (session_token, expiry, vault_version).<br>8. Sesja przechodzi w stan ESTABLISHED. |
| **Scenariusze alternatywne / błędy** | **A1 – Błędne hasło:** Serwer odsyła `AUTH_FAIL(ERR_AUTH_FAILED)`; klient wyświetla komunikat błędu; użytkownik może ponowić (maks. 5 prób / 15 min / IP).<br>**A2 – Rate limiting:** Po 5 nieudanych próbach serwer zwraca `AUTH_FAIL(ERR_RATE_LIMITED, retry_after=900)`; klient blokuje interfejs na wskazany czas.<br>**A3 – Błąd zegara:** Timestamp w HELLO odbiega o >5 min; serwer zwraca `ERROR(ERR_CLOCK_SKEW)`; klient synchronizuje czas i ponawia.<br>**A4 – Brak sieci:** Timeout TLS handshake (10 s); klient wyświetla błąd połączenia i oferuje tryb offline z lokalną kopią. |
| **Wynik końcowy** | Sesja w stanie ESTABLISHED; klient posiada aktywny session_token (ważny 24h) i znany vault_version |

---

### UC-02: Pobieranie sejfu (synchronizacja)

| Pole | Opis |
|---|---|
| **Cel** | Pobranie aktualnej wersji zaszyfrowanego sejfu z serwera i odszyfrowanie go lokalnie |
| **Aktor** | Użytkownik (po zalogowaniu) |
| **Warunki wstępne** | Sesja w stanie ESTABLISHED; użytkownik posiada vault_id |
| **Scenariusz główny** | 1. Po uzyskaniu AUTH_OK klient porównuje odebrany `vault_version` z wersją lokalnej kopii.<br>2. Jeśli wersja serwera jest wyższa — klient wysyła `VAULT_GET(vault_id, known_version)`.<br>3. Serwer odnajduje sejf w bazie i odsyła `VAULT_DATA(vault_id, version, blob)`.<br>4. Jeśli blob jest duży (>1 MB), jest przesyłany w fragmentach (flaga FRAGMENTED).<br>5. Klient składa fragmenty, weryfikuje HMAC każdej ramki.<br>6. Klient deszyfruje blob kluczem pochodnym hasła głównego (AES-256-GCM).<br>7. Odszyfrowane wpisy ładowane są do pamięci RAM. |
| **Scenariusze alternatywne / błędy** | **A1 – Wersja lokalna aktualna:** `known_version == vault_version`; klient nie wysyła VAULT_GET i korzysta z lokalnej kopii.<br>**A2 – Sejf nie istnieje:** Serwer zwraca `ERROR(ERR_NOT_FOUND)`; klient inicjuje pusty nowy sejf.<br>**A3 – Utrata połączenia podczas fragmentacji:** TCP zerwany; serwer odrzuca niekompletne fragmenty po 30 s; klient po wznowieniu sesji (UC-05) pobiera całość od nowa.<br>**A4 – Błąd HMAC fragmentu:** Natychmiastowy TCP RST; klient inicjuje nowe połączenie. |
| **Wynik końcowy** | Klient posiada aktualny, odszyfrowany sejf w pamięci RAM; interfejs wyświetla wpisy |

---

### UC-03: Zapis zmodyfikowanego sejfu

| Pole | Opis |
|---|---|
| **Cel** | Wysłanie zaktualizowanego, zaszyfrowanego sejfu na serwer |
| **Aktor** | Użytkownik |
| **Warunki wstępne** | Sesja ESTABLISHED; użytkownik dokonał zmian w lokalnym sejfie |
| **Scenariusz główny** | 1. Użytkownik zapisuje zmiany (np. dodaje nowe hasło).<br>2. Klient szyfruje całość sejfu nowym losowym IV (AES-256-GCM).<br>3. Klient wysyła `VAULT_PUT(vault_id, base_version, blob)` gdzie `base_version` to ostatnia znana wersja.<br>4. Serwer sprawdza: `aktualna_wersja_w_bazie == base_version` (CAS check).<br>5. Jeśli zgodne — serwer zapisuje blob, inkrementuje wersję.<br>6. Serwer odsyła `VAULT_ACK(vault_id, new_version)`.<br>7. Klient aktualizuje lokalny `vault_version`. |
| **Scenariusze alternatywne / błędy** | **A1 – Konflikt wersji:** Serwer zwraca `ERROR(ERR_CONFLICT)` (inna wersja na serwerze); klient pobiera aktualizację (UC-02), scala zmiany lokalnie, ponawia VAULT_PUT.<br>**A2 – Sejf zbyt duży (>50 MB):** Serwer zwraca `ERROR(ERR_TOO_LARGE)`; klient informuje użytkownika o przekroczeniu limitu.<br>**A3 – Token wygasł w trakcie zapisu:** Serwer zwraca `ERROR(ERR_SESSION_EXPIRED)`; klient wznawia sesję (UC-05) i ponawia zapis.<br>**A4 – Rate limiting:** Po 60 żądań VAULT_* / min serwer zwraca `ERR_RATE_LIMITED` z polem `retry_after`. |
| **Wynik końcowy** | Serwer przechowuje nową wersję sejfu; oba urządzenia (jeśli więcej niż jedno) są informowane o nowej wersji przy kolejnym połączeniu |

---

### UC-04: Rozwiązywanie konfliktu wersji (scalanie)

| Pole | Opis |
|---|---|
| **Cel** | Scalenie zmian dokonanych równocześnie na dwóch urządzeniach użytkownika |
| **Aktor** | Użytkownik (urządzenie B) |
| **Warunki wstępne** | Urządzenie A pomyślnie zapisało nową wersję sejfu (ver. 43); urządzenie B posiada lokalną wersję 42 i próbuje zapisać swoje zmiany |
| **Scenariusz główny** | 1. Urządzenie B wysyła `VAULT_PUT(base_version=42, blob_B)`.<br>2. Serwer wykrywa konflikt (aktualna wersja = 43) i zwraca `ERROR(ERR_CONFLICT)`.<br>3. Klient na urządzeniu B wysyła `VAULT_GET(known_version=43)`.<br>4. Serwer odsyła `VAULT_DATA(version=43, blob_A)`.<br>5. Klient B deszyfruje blob_A i identyfikuje różnicę z lokalną wersją 42.<br>6. Klient B scala: wpisy zmienione tylko w A → z A; zmienione tylko w B → z B; zmienione w obu → sygnalizacja konfliktu użytkownikowi z wyborem.<br>7. Scalony sejf jest szyfrowany i wysyłany jako `VAULT_PUT(base_version=43, blob_merged)`.<br>8. Serwer zapisuje i odsyła `VAULT_ACK(new_version=44)`. |
| **Scenariusze alternatywne / błędy** | **A1 – Użytkownik rezygnuje ze scalania:** Klient odrzuca lokalne zmiany i aktualizuje do wersji serwerowej.<br>**A2 – Kolejny konflikt podczas scalania:** Bardzo mało prawdopodobne przy jednym użytkowniku; ponowne pobranie i scalanie. |
| **Wynik końcowy** | Obie wersje scalone w jedną spójną wersję na serwerze; oba urządzenia zsynchronizowane po następnym pobraniu |

---

### UC-05: Automatyczne wznowienie sesji po utracie połączenia

| Pole | Opis |
|---|---|
| **Cel** | Przywrócenie aktywnej sesji SVP bez ponownego podawania hasła przez użytkownika |
| **Aktor** | Klient (automatycznie, bez interakcji użytkownika) |
| **Warunki wstępne** | Połączenie TCP zostało zerwane; session_token jest wciąż ważny (< 24h od wydania) |
| **Scenariusz główny** | 1. Klient wykrywa zerwanie TCP (RST / EOF / brak PONG przez 3 × 30 s).<br>2. Klient przechodzi w stan DISCONNECTED i odczekuje backoff `exp(1×2^n s)`, max 60 s ±10% jitter.<br>3. Klient nawiązuje nowe połączenie TCP + TLS 1.3.<br>4. Klient wysyła `HELLO(client_id, nonce_c, timestamp)`.<br>5. Serwer odsyła `CHALLENGE`.<br>6. Klient wysyła `AUTH(login, token_refresh=0x01, session_token=<stary>)` — bez hmac_resp.<br>7. Serwer weryfikuje session_token (podpis, expiry, client_id binding).<br>8. Serwer odsyła `AUTH_OK(nowy_token, vault_version)` — stary token unieważniony.<br>9. Sesja powraca do stanu ESTABLISHED. |
| **Scenariusze alternatywne / błędy** | **A1 – Token wygasł:** Serwer zwraca `ERROR(ERR_SESSION_EXPIRED)`; klient prosi użytkownika o podanie hasła (UC-01).<br>**A2 – Serwer niedostępny:** Kolejne próby z rosnącym backoff; klient oferuje tryb offline.<br>**A3 – Zmieniony client_id:** Serwer odrzuca token (binding mismatch); wymagane pełne logowanie. |
| **Wynik końcowy** | Sesja wznowiona przezroczyście dla użytkownika; kontynuacja przerwanej operacji |

---

### UC-06: Logowanie z uwierzytelnieniem dwuskładnikowym (TOTP)

| Pole | Opis |
|---|---|
| **Cel** | Zalogowanie się użytkownika z włączonym 2FA (TOTP) |
| **Aktor** | Użytkownik z aktywnym TOTP |
| **Warunki wstępne** | Konto ma aktywowany TOTP (totp_secret zapisany na serwerze); użytkownik ma dostęp do aplikacji TOTP |
| **Scenariusz główny** | 1. Kroki 1–5 jak w UC-01 (HELLO → CHALLENGE → obliczenie hmac_resp).<br>2. Użytkownik otwiera aplikację TOTP i odczytuje aktualny 6-cyfrowy kod.<br>3. Klient wysyła `AUTH(login, hmac_resp, totp_present=0x01, totp_code=<kod>)`.<br>4. Serwer weryfikuje hmac_resp ORAZ kod TOTP (RFC 6238, okno ±30 s).<br>5. Serwer odsyła `AUTH_OK`. |
| **Scenariusze alternatywne / błędy** | **A1 – Błędny kod TOTP:** Serwer zwraca `AUTH_FAIL(ERR_AUTH_FAILED)`; błędny TOTP wlicza się do limitu 5 prób.<br>**A2 – Kod TOTP przeterminowany:** Użytkownik wpisał kod ze starego okna 30-sekundowego; serwer odrzuca (okno weryfikacji ±1 krok = ±30 s); klient prosi o nowy kod.<br>**A3 – Użytkownik nie ma dostępu do TOTP:** Użycie kodów zapasowych (poza zakresem SVP — zarządzane przez warstwę aplikacyjną). |
| **Wynik końcowy** | Sesja ESTABLISHED z potwierdzonym drugim składnikiem; wyższy poziom bezpieczeństwa konta |

---

## 4. Mapowanie aplikacji na protokół

### 4.1 Funkcje aplikacji a komunikaty SVP

| Funkcja aplikacji | Komunikaty SVP | Uwagi |
|---|---|---|
| Logowanie | `HELLO` → `CHALLENGE` → `AUTH` → `AUTH_OK` / `AUTH_FAIL` | Challenge-response bez przesyłania hasła |
| Logowanie z TOTP | `AUTH` z polami `totp_present=0x01, totp_code` | Dodatkowe pole w istniejącym komunikacie |
| Pobieranie sejfu | `VAULT_GET` → `VAULT_DATA` | Fragmentacja przy blob >1 MB |
| Zapis sejfu | `VAULT_PUT` → `VAULT_ACK` / `ERROR(ERR_CONFLICT)` | CAS check przez pole `base_version` |
| Sync różnicowy | `VAULT_SYNC` → `VAULT_ACK` | Redukcja transferu przy małych zmianach |
| Rozwiązywanie konfliktu | `VAULT_GET` (po ERR_CONFLICT) + `VAULT_PUT` | Scalanie po stronie klienta |
| Keep-alive / aktywność sesji | `PING` → `PONG` (co 30 s) | Wykrywanie martwych połączeń |
| Wznowienie sesji tokenem | `AUTH` z `token_refresh=0x01` | Bez ponownego podawania hasła |
| Zamknięcie sesji | `BYE(reason=NORMAL)` | Grzeczne zamknięcie TCP |
| Obsługa błędów protokołu | `ERROR` (kody 0x01–0xFF) | Nieodwracalne błędy → TCP RST |

### 4.2 Jak protokół wspiera przypadki użycia

**UC-01 (Logowanie)** — w pełni realizowany przez sekwencję `HELLO → CHALLENGE → AUTH → AUTH_OK`. Pole `nonce_c` i `nonce_s` eliminują ataki replay. Pole `timestamp` chroni przed atakami z opóźnieniem (ERR_CLOCK_SKEW). Rate-limiting (ERR_RATE_LIMITED) chroni przed brute-force.

**UC-02 (Pobieranie sejfu)** — `VAULT_GET` z polem `known_version` pozwala serwerowi zdecydować, czy przesyłać pełny blob. Flagi `FRAGMENTED` i `LAST_FRAG` obsługują duże sejfy bez ograniczeń pamięci RAM serwera. HMAC każdej ramki gwarantuje integralność fragmentów.

**UC-03 (Zapis sejfu)** — `VAULT_PUT` z `base_version` implementuje optimistic locking: serwer odrzuca zapis, jeśli wersja nie zgadza się z aktualną (ERR_CONFLICT), co eliminuje ciche nadpisanie zmian.

**UC-04 (Scalanie)** — protokół nie definiuje algorytmu scalania (to logika aplikacji), ale zapewnia infrastrukturę: ERR_CONFLICT sygnalizuje konieczność scalania, VAULT_GET dostarcza aktualną wersję, ponowny VAULT_PUT wysyła scalone dane.

**UC-05 (Wznowienie sesji)** — pole `token_refresh=0x01` w komunikacie `AUTH` pozwala pominąć pełny challenge-response przy ważnym tokenie. Token zawiera `session_uuid` i binding do `client_id`, co uniemożliwia kradzież tokena przez inny klient.

**UC-06 (TOTP)** — pola `totp_present` i `totp_code` w `AUTH` dodają drugi składnik bez konieczności dodatkowego round-tripu do serwera.

### 4.3 Ewentualne rozszerzenia protokołu

| Rozszerzenie | Uzasadnienie | Proponowany komunikat |
|---|---|---|
| `VAULT_SHARE` (C→S) | Udostępnianie wybranych wpisów innemu użytkownikowi przez zaszyfrowanie kluczem publicznym odbiorcy | Nowy typ 0x15 |
| `NOTIFY` (S→C) | Powiadomienie push o nowej wersji sejfu (inny klient zapisał zmiany) — eliminuje polling | Nowy typ 0x30; wymaga połączenia długotrwałego |
| `AUDIT_LOG_GET` (C→S) | Pobieranie historii zdarzeń konta (logowania, zmiany) — użyteczne dla zaawansowanych użytkowników | Nowy typ 0x40 |
| Pole `device_name` w HELLO | Identyfikacja urządzenia czytelna dla użytkownika (np. „MacBook Pro Alice") w historii sesji | Rozszerzenie payload 0x01 |

---

## 5. Wymagania niefunkcjonalne

### 5.1 Bezpieczeństwo

- **Poufność:** Wszystkie dane transmitowane przez TLS 1.3 (cipher suites AEAD). Blob sejfu szyfrowany AES-256-GCM po stronie klienta — model zero-knowledge.
- **Integralność:** HMAC-SHA256 każdej ramki SVP; klucz pochodny z session_token przez HKDF. Niezgodność → TCP RST.
- **Uwierzytelnienie:** Challenge-response z PBKDF2 (200 000 iteracji); hasło główne nigdy nie opuszcza klienta. Opcjonalne TOTP (RFC 6238).
- **Ochrona przed replay:** nonce_c, nonce_s, timestamp (±5 min), SEQ_ID (okno 1024), krótki TTL tokena (24h).
- **Rate limiting:** Maks. 5 prób logowania / 15 min / IP; maks. 60 żądań VAULT_* / min; maks. 10 połączeń jednoczesnych / IP.
- **Certyfikaty:** Weryfikacja X.509; opcjonalny certificate pinning w produkcji.
- **Timing attacks:** Porównanie HMAC metodą constant-time (`hmac.compare_digest`).

### 5.2 Wydajność

| Parametr | Cel |
|---|---|
| Liczba jednoczesnych klientów | ≥ 1 000 (przy skalowaniu poziomym) |
| Opóźnienie logowania (RTT) | < 500 ms w sieci LAN, < 2 s przez internet |
| Czas pobrania sejfu 1 MB | < 3 s (przy łączu 10 Mbit/s) |
| Czas zapisu sejfu 1 MB | < 3 s |
| Czas keep-alive (PING/PONG) | < 100 ms w sieci LAN |
| Maks. rozmiar sejfu | 50 MB (skompresowany blob) |

Kompresja (flaga COMPRESSED, zlib deflate) zalecana dla sejfów >100 kB — oczekiwany stopień kompresji 3–5× dla danych JSON/tekstowych.

### 5.3 Niezawodność

- **Odporność na zerwanie połączenia:** Automatyczne wznawianie sesji tokenem (UC-05); backoff wykładniczy z jitterem (max 60 s).
- **Obsługa fragmentacji:** Niekompletne fragmenty odrzucane po 30 s i zwalniane; klient ponawia pełną transmisję.
- **Duplikaty:** Ciche odrzucanie ramek z SEQ_ID ≤ ostatniemu odebranemu (okno 1024).
- **Dostępność trybu offline:** Klient przechowuje lokalną kopię zaszyfrowanego bloba; odczyt możliwy bez połączenia (zapis dopiero po synchronizacji).
- **Keep-alive:** PING co 30 s; po 3 nieodebranych PONG (90 s) sesja uznana za martwą i zamknięta.

### 5.4 Skalowalność

- **Pozioma (serwer):** Architektura bezstanowa na poziomie protokołu — sesje identyfikowane tokenem, możliwy load balancer. Baza danych jako jedyny stan współdzielony.
- **Wertykalna:** Serwer jednowątkowy może obsłużyć ~100 klientów (I/O-bound); z pula wątków lub event loop (asyncio/epoll) — tysiące klientów.
- **Przyszłościowa:** Dodanie `VAULT_SHARE` (sekcja 4.3) umożliwi rozszerzenie na tryb zespołowy bez zmiany rdzenia protokołu.

### 5.5 Logowanie i diagnostyka

| Zdarzenie | Poziom | Zawartość logu |
|---|---|---|
| Nowe połączenie TCP | INFO | IP klienta, port, timestamp |
| HELLO odebrany | DEBUG | client_id (UUID), wersja klienta |
| AUTH sukces | INFO | username (hash), client_id, vault_version |
| AUTH fail | WARN | username (hash), IP, numer próby |
| Rate limit aktywowany | WARN | IP, próg, retry_after |
| VAULT_PUT sukces | INFO | vault_id (UUID), nowa wersja, rozmiar bloba |
| ERR_CONFLICT | INFO | vault_id, base_version klienta, aktualna wersja |
| TCP RST (ERR_BAD_HMAC) | WARN | IP, SEQ_ID, timestamp |
| Sesja zakończona | INFO | username (hash), czas trwania, powód (BYE/timeout) |
| Błąd wewnętrzny | ERROR | stack trace, kontekst sesji |

Logi: rotacja dzienna, retencja 30 dni, format JSON (kompatybilny z Elasticsearch / Grafana Loki). Wrażliwe pola (username) zastępowane SHA-256(username) w logach produkcyjnych.

---

## 6. Plan implementacji i testowania

### 6.1 Zakres MVP

MVP (Minimum Viable Product) obejmuje kompletną ścieżkę: logowanie → pobieranie sejfu → edycja → zapis.

**Serwer (Python / asyncio):**
- [ ] Moduł TLS: nasłuch na porcie 7443, TLS 1.3, weryfikacja certyfikatu
- [ ] Parser ramek SVP: nagłówek 11B + PAYLOAD + HMAC weryfikacja
- [ ] Obsługa komunikatów: HELLO, CHALLENGE, AUTH, AUTH_OK, AUTH_FAIL
- [ ] Obsługa komunikatów: VAULT_GET, VAULT_PUT, VAULT_DATA, VAULT_ACK
- [ ] Obsługa: PING/PONG, BYE, ERROR
- [ ] Baza SQLite: tabele `users`, `vaults`, `sessions`
- [ ] Rate limiting per IP (in-memory, resetowany co 15 min)

**Klient (Python CLI):**
- [ ] Moduł połączenia TLS
- [ ] Implementacja sekwencji AUTH (PBKDF2, HMAC-SHA256)
- [ ] Lokalna pamięć podręczna sejfu (plik `.json.enc`)
- [ ] Deszyfrowanie / szyfrowanie AES-256-GCM
- [ ] Komendy CLI: `login`, `get`, `add`, `edit`, `delete`, `sync`, `logout`

**Poza MVP (v2.0):**
- Klient GUI (PyQt / Electron)
- TOTP (UC-06)
- Sync różnicowy (VAULT_SYNC)
- Skalowanie: PostgreSQL, wielowątkowy serwer
- Certificate pinning

### 6.2 Podział pracy między dwie osoby

Podział oparty jest na granicy **serwer ↔ klient**: każda osoba odpowiada za jeden spójny obszar od warstwy sieciowej aż po testy swojej części. Interfejsem współdzielonym jest format ramki SVP (nagłówek + HMAC) — obie osoby ustalają go na początku i traktują jako kontrakt.

---

#### Osoba A — Serwer SVP

Odpowiada za całą stronę serwerową: stos sieciowy, logikę protokołu, bazę danych oraz testy integracyjne serwera (z klientem-zaślepką).

**Tydzień 1 — fundament sieciowy + autentykacja**
- [ ] Szkielet asyncio: nasłuch TCP na porcie 7443, TLS 1.3, obsługa wielu połączeń jednocześnie
- [ ] Parser / serializer ramek SVP — nagłówek 11B, length-prefix framing, weryfikacja HMAC-SHA256
- [ ] Obsługa stanów sesji: DISCONNECTED → GREETING → AUTHENTICATING → ESTABLISHED → CLOSING
- [ ] Obsługa PING/PONG (keep-alive co 30 s, timeout 90 s) i BYE
- [ ] Obsługa HELLO → CHALLENGE (generowanie nonce_s, weryfikacja timestamp ±5 min)
- [ ] Obsługa AUTH → AUTH_OK / AUTH_FAIL (weryfikacja hmac_resp, constant-time compare)
- [ ] Generowanie i weryfikacja session_token (HMAC-SHA256, binding do client_id, TTL 24h)
- [ ] Odświeżanie sesji tokenem (`token_refresh=0x01`) — UC-05
- [ ] Rate limiting: maks. 5 prób AUTH / 15 min / IP; maks. 60 VAULT_* / min; maks. 10 połączeń / IP

**Tydzień 2 — logika sejfów, baza danych, testy**
- [ ] Schemat SQLite: tabele `users`, `vaults`, `sessions`
- [ ] Obsługa VAULT_GET → VAULT_DATA (fragmentacja przy blob >1 MB, flaga FRAGMENTED/LAST_FRAG)
- [ ] Obsługa VAULT_PUT → VAULT_ACK z CAS check (base_version == aktualna wersja) → ERR_CONFLICT
- [ ] Obsługa błędów protokołu: ERROR z kodami 0x01–0xFF, eskalacja po 3 błędach łagodnych / 60 s
- [ ] Czyszczenie niekompletnych fragmentów po 30 s
- [ ] Testy jednostkowe parsera ramek i modułu HMAC
- [ ] Testy integracyjne z klientem-zaślepką: TF-01, TF-02, TF-03, TF-04, TF-05, TF-08, TF-09
- [ ] Testy bezpieczeństwa: TS-01 – TS-10 (skrypt wysyłający złośliwe ramki)
- [ ] Testy obciążeniowe: TL-01, TL-02, TL-03, TL-04
- [ ] Moduł logowania JSON (zdarzenia z sekcji 5.5), rotacja dzienna

**Zależności zewnętrzne Osoby A:** biblioteki `cryptography` (TLS, HMAC, HKDF), `aiosqlite`, Python 3.11+. Nie zależy od kodu Osoby B — testuje przez zaślepkę.

---

#### Osoba B — Klient SVP + moduł kryptograficzny

Odpowiada za całą stronę kliencką: warstwę sieciową klienta, logikę kryptograficzną, lokalną pamięć sejfu i interfejs CLI.

**Tydzień 1 — moduł kryptograficzny + warstwa sieciowa klienta**
- [ ] Moduł krypto (`crypto.py`): PBKDF2-HMAC-SHA256 (200 000 iteracji), HKDF, HMAC-SHA256 constant-time
- [ ] Szyfrowanie / deszyfrowanie AES-256-GCM (generowanie IV, weryfikacja GCM_TAG)
- [ ] Derywacja K_auth i obliczanie hmac_resp z nonce_c, nonce_s, username
- [ ] Testy jednostkowe modułu krypto (pokrycie ≥ 90 %): wektory testowe NIST dla AES-GCM, PBKDF2
- [ ] Moduł połączenia TLS (weryfikacja certyfikatu X.509, opcjonalny pinning)
- [ ] Serializer / parser ramek SVP (współdzielony kontrakt z Osobą A)
- [ ] Implementacja sekwencji logowania: HELLO → CHALLENGE → AUTH → AUTH_OK (UC-01)
- [ ] Implementacja odświeżania sesji tokenem: AUTH z `token_refresh=0x01` (UC-05)
- [ ] PING/PONG (keep-alive po stronie klienta, reconnect z backoff wykładniczym)

**Tydzień 2 — logika sejfu, CLI, testy integracyjne**
- [ ] Lokalna pamięć podręczna: szyfrowany plik `.svp_cache` (AES-256-GCM), odczyt offline
- [ ] VAULT_GET → odbiór VAULT_DATA (składanie fragmentów, deszyfrowanie)
- [ ] VAULT_PUT → obsługa VAULT_ACK i ERR_CONFLICT (scalanie lokalne + ponowny PUT) — UC-03, UC-04
- [ ] Zarządzanie wpisami w pamięci RAM: dodawanie, edycja, usuwanie, wyszukiwanie
- [ ] CLI (`svp-cli`): komendy `login`, `logout`, `get <id>`, `add`, `edit <id>`, `delete <id>`, `sync`, `list`
- [ ] Testy integracyjne z serwerem Osoby A: TF-01 – TF-09
- [ ] Test UC-04 (konflikt): dwa procesy klienta zapisują równocześnie, weryfikacja scalania
- [ ] Test trybu offline: klient bez połączenia odczytuje lokalną kopię

**Zależności zewnętrzne Osoby B:** biblioteki `cryptography`, `click` (CLI). Potrzebuje działającego serwera Osoby A do testów integracyjnych (od połowy tygodnia 2); wcześniej mockuje odpowiedzi.

---

#### Punkt synchronizacji (koniec dnia 3. — środa tygodnia 1.)

Obie osoby uzgadniają i zamrażają wspólny **kontrakt binarny ramki SVP**:

```
- Stały nagłówek: VERSION(1B) | MSG_TYPE(1B) | FLAGS(1B) | SEQ_ID(4B) | PAYLOAD_LEN(4B)
- Trailer: HMAC-SHA256(32B) obliczany z nagłówka + PAYLOAD
- Klucz HMAC: K_mac = HKDF-SHA256(session_token, salt=nonce_c, info='svp-mac', len=32)
- Kodowanie: little-endian, unsigned integers
```

Po zamrożeniu kontraktu obie osoby mogą pracować w pełni niezależnie.

---

### 6.3 Plan testów

#### Testy funkcjonalne

| ID | Opis | Prowadzi | Oczekiwany wynik |
|---|---|---|---|
| TF-01 | Poprawne logowanie (UC-01) | Osoba B | AUTH_OK, session_token ważny |
| TF-02 | Błędne hasło | Osoba B | AUTH_FAIL(ERR_AUTH_FAILED) |
| TF-03 | Pobieranie sejfu (UC-02) | Osoba B | VAULT_DATA z poprawnym blob |
| TF-04 | Zapis sejfu bez konfliktu (UC-03) | Osoba B | VAULT_ACK z new_version = old+1 |
| TF-05 | Zapis z konfliktem (UC-04) | Osoba B | ERR_CONFLICT, następnie scalanie i VAULT_ACK |
| TF-06 | Wznowienie sesji tokenem (UC-05) | Osoba B | AUTH_OK bez podania hasła |
| TF-07 | Logowanie z TOTP (UC-06) | Osoba B | AUTH_OK po poprawnym kodzie TOTP |
| TF-08 | BYE — grzeczne zamknięcie | Osoba A | TCP FIN po obu stronach |
| TF-09 | Fragmentacja dużego sejfu | Osoba A | Poprawne złożenie i VAULT_ACK |

#### Testy błędów i bezpieczeństwa

| ID | Opis | Prowadzi | Oczekiwany wynik |
|---|---|---|---|
| TS-01 | Błędny HMAC ramki | Osoba A | Natychmiastowy TCP RST |
| TS-02 | Replay ataku (ten sam SEQ_ID) | Osoba A | Ciche odrzucenie |
| TS-03 | Stary timestamp w HELLO (>5 min) | Osoba A | ERROR(ERR_CLOCK_SKEW) |
| TS-04 | 6 prób logowania / 15 min z jednego IP | Osoba A | ERR_RATE_LIMITED po 5. próbie |
| TS-05 | Nieznany MSG_TYPE | Osoba A | ERROR(ERR_UNKNOWN_TYPE), sesja trwa |
| TS-06 | PAYLOAD_LEN > 1 MB | Osoba A | ERROR(ERR_TOO_LARGE) |
| TS-07 | Zerwanie połączenia w trakcie VAULT_PUT | Osoba A | Serwer odrzuca fragmenty po 30 s |
| TS-08 | Żądanie cudzego vault_id | Osoba A | ERROR(ERR_FORBIDDEN) |
| TS-09 | Wygasły session_token | Osoba A | ERROR(ERR_SESSION_EXPIRED) |
| TS-10 | Połączenie bez TLS (gołe TCP) | Osoba A | Odrzucenie na poziomie TLS |

#### Testy obciążeniowe (podstawowe)

| ID | Opis | Prowadzi | Kryterium sukcesu |
|---|---|---|---|
| TL-01 | 100 równoczesnych logowań | Osoba A | Wszystkie AUTH_OK w < 5 s |
| TL-02 | 50 równoczesnych VAULT_PUT 1 MB | Osoba A | Wszystkie VAULT_ACK w < 30 s |
| TL-03 | 1000 PING/PONG w ciągu 1 min | Osoba A | Brak timeoutów, średni RTT < 50 ms |
| TL-04 | Sejf 50 MB (maks.) | Osoba A | VAULT_DATA dostarczone, VAULT_ACK |

### 6.4 Harmonogram (2 tygodnie)

| Dzień | Osoba A (Serwer) | Osoba B (Klient) | Kamień milowy |
|---|---|---|---|
| 1–3 (Pn–Śr, tydz. 1) | TCP + TLS + parser ramek + stany sesji | Moduł krypto: PBKDF2, AES-GCM, testy jednostkowe | **Śr. tydz. 1: zamrożenie kontraktu binarnego SVP** |
| 4–5 (Czw–Pt, tydz. 1) | AUTH, rate limiting, session token, UC-05 | Warstwa sieciowa klienta, logowanie, PING/PONG | Logowanie działa end-to-end (piątek tydz. 1) |
| 6–8 (Pn–Śr, tydz. 2) | VAULT_GET/PUT, SQLite, fragmentacja, obsługa błędów | Lokalny cache, CLI, obsługa konfliktu UC-04 | Pełny przepływ MVP działa (środa tydz. 2) |
| 9–10 (Czw–Pt, tydz. 2) | Testy TS-*, TL-*, logowanie JSON | Testy integracyjne TF-*, test konfliktu, test offline | **Pt. tydz. 2: wszystkie kryteria MVP spełnione** |

### 6.5 Kryteria zakończenia MVP

- Testy TF-01 – TF-09: wszystkie PASS
- Testy TS-01 – TS-10: wszystkie PASS
- Testy obciążeniowe TL-01 i TL-03: PASS
- Brak błędów krytycznych (przyjęty błędny HMAC, token bez weryfikacji expiry, brak CAS check)
- Pokrycie testami jednostkowymi modułu krypto (Osoba B): ≥ 90 %
- Logi serwera generowane poprawnie dla zdarzeń z sekcji 5.5

---

*Dokument przygotowany na podstawie specyfikacji SecVault Protocol (SVP v1.0) — Etap 1.*
