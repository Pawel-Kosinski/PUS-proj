// main.cpp - interfejs CLI (REPL) klienta SecVault.
// Sejf żyje w pamięci RAM przez czas sesji; hasło główne nigdy nie jest zapisywane.
#include <termios.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include "client.h"
#include "crypto.h"
#include "vault.h"

using namespace svp;

namespace {

// ---- wejście użytkownika ----
std::string read_line(const std::string& prompt) {
    std::cout << prompt << std::flush;
    std::string s;
    if (!std::getline(std::cin, s)) return "";
    return s;
}

// Odczyt hasła bez echa w terminalu (odpowiednik getpass).
std::string read_password(const std::string& prompt) {
    std::cout << prompt << std::flush;
    termios oldt{};
    bool tty = isatty(STDIN_FILENO);
    if (tty) {
        tcgetattr(STDIN_FILENO, &oldt);
        termios newt = oldt;
        newt.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    }
    std::string pw;
    std::getline(std::cin, pw);
    if (tty) {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        std::cout << "\n";
    }
    return pw;
}

// ---- lokalna pamięć podręczna (offline) ----
constexpr char CACHE_MAGIC[8] = {'S', 'V', 'C', 'A', 'C', 'H', 'E', '1'};

void save_cache(const std::string& path, const std::string& login, const Bytes& vault_id,
                uint32_t version, const Bytes& blob) {
    ByteWriter w;
    w.raw(reinterpret_cast<const uint8_t*>(CACHE_MAGIC), sizeof(CACHE_MAGIC));
    w.lpstr(login);
    w.raw(vault_id);
    w.u32(version);
    w.lpblob(blob);
    Bytes out = w.take();
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(out.data()), out.size());
}

bool load_cache(const std::string& path, std::string& login, Bytes& vault_id, uint32_t& version,
                Bytes& blob) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    std::stringstream ss;
    ss << f.rdbuf();
    std::string data = ss.str();
    Bytes raw(data.begin(), data.end());
    try {
        ByteReader r(raw);
        Bytes magic = r.raw(sizeof(CACHE_MAGIC));
        if (std::memcmp(magic.data(), CACHE_MAGIC, sizeof(CACHE_MAGIC)) != 0) return false;
        login = r.lpstr();
        vault_id = r.raw(VAULT_ID_LEN);
        version = r.u32();
        blob = r.lpblob();
        return true;
    } catch (...) {
        return false;
    }
}

void print_entry(const Entry& e, bool show_password) {
    std::cout << "  id:       " << e.id << "\n";
    std::cout << "  serwis:   " << e.service << "\n";
    std::cout << "  login:    " << e.username << "\n";
    std::cout << "  hasło:    " << (show_password ? e.password : std::string("********")) << "\n";
    if (!e.notes.empty()) std::cout << "  notatka:  " << e.notes << "\n";
}

// ---- self-test kryptografii (KAT + roundtrip) ----
int selftest() {
    using namespace svp::crypto;
    int fails = 0;
    auto check = [&](const std::string& name, bool ok) {
        std::cout << (ok ? "[ OK ] " : "[FAIL] ") << name << "\n";
        if (!ok) ++fails;
    };

    // SHA256("abc") - znany wektor.
    check("SHA256(\"abc\")",
          to_hex(sha256(to_bytes("abc"))) ==
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    // HMAC-SHA256 RFC 4231 test case 1.
    Bytes key(20, 0x0b);
    check("HMAC-SHA256 (RFC 4231 #1)",
          to_hex(hmac_sha256(key, to_bytes("Hi There"))) ==
              "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    // AES-256-GCM roundtrip + wykrywanie modyfikacji.
    Bytes vk = random_bytes(32), iv = random_bytes(12), tag;
    Bytes pt = to_bytes("tajne hasło 123");
    Bytes ct = aes256gcm_encrypt(vk, iv, pt, {}, tag);
    check("AES-256-GCM roundtrip", aes256gcm_decrypt(vk, iv, ct, {}, tag) == pt);
    bool detected = false;
    ct[0] ^= 0x01;
    try { aes256gcm_decrypt(vk, iv, ct, {}, tag); } catch (...) { detected = true; }
    check("AES-256-GCM wykrywa modyfikację", detected);

    // PBKDF2 + HKDF: determinizm i rozdzielność kluczy.
    Bytes a = pbkdf2_sha256("pass", sha256(to_bytes("user")), 1000, 32);
    Bytes b = pbkdf2_sha256("pass", sha256(to_bytes("user")), 1000, 32);
    check("PBKDF2 determinizm", a == b);
    Bytes m1 = hkdf_sha256(a, iv, "svp-mac", 32);
    Bytes m2 = hkdf_sha256(a, iv, "svp-mac", 32);
    check("HKDF determinizm", m1 == m2);
    check("HKDF różne info -> różny klucz", hkdf_sha256(a, iv, "x", 32) != hkdf_sha256(a, iv, "y", 32));

    // Sejf: szyfrowanie -> deszyfrowanie zachowuje wpisy.
    Vault v;
    v.add("github.com", "alice", "s3cr3t", "konto firmowe");
    Bytes blob = v.encrypt(vk);
    Vault v2 = Vault::decrypt(blob, vk);
    check("Vault encrypt/decrypt", v2.size() == 1 && v2.entries()[0].password == "s3cr3t");

    std::cout << "\n" << (fails ? "NIEPOWODZENIE" : "Wszystkie testy OK") << " (" << fails
              << " błędów)\n";
    return fails ? 1 : 0;
}

void print_help() {
    std::cout <<
        "Dostępne komendy:\n"
        "  ls                 - lista wpisów\n"
        "  get <serwis|id>    - pokaż wpis wraz z hasłem\n"
        "  add                - dodaj nowy wpis\n"
        "  edit <serwis|id>   - edytuj wpis\n"
        "  rm  <serwis|id>    - usuń wpis\n"
        "  sync               - wyślij zmiany na serwer (z obsługą konfliktu)\n"
        "  pull               - pobierz i scal wersję z serwera\n"
        "  ping               - test połączenia (keep-alive)\n"
        "  help               - ta pomoc\n"
        "  quit / exit        - synchronizuj i zakończ\n";
}

struct Args {
    ClientConfig cfg;
    std::string cache = ".svp_cache";
    bool selftest = false;
    bool offline = false;
};

Args parse_args(int argc, char** argv) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        auto next = [&]() -> std::string { return (i + 1 < argc) ? argv[++i] : ""; };
        if (s == "--host") a.cfg.host = next();
        else if (s == "--port") a.cfg.port = static_cast<uint16_t>(std::stoi(next()));
        else if (s == "--ca") a.cfg.ca_file = next();
        else if (s == "--insecure") a.cfg.insecure = true;
        else if (s == "--debug") a.cfg.debug = true;
        else if (s == "--cache") a.cache = next();
        else if (s == "--offline") a.offline = true;
        else if (s == "--selftest") a.selftest = true;
        else if (s == "-h" || s == "--help") {
            std::cout << "Użycie: secvault [--host H] [--port P] [--ca plik.pem] [--insecure]\n"
                         "                [--cache plik] [--offline] [--debug] [--selftest]\n";
            std::exit(0);
        } else {
            std::cerr << "Nieznany argument: " << s << "\n";
            std::exit(2);
        }
    }
    return a;
}

// Synchronizacja z obsługą konfliktu (UC-03/UC-04).
bool do_sync(Client& cli, Vault& vault) {
    cli.ensure_session();
    for (int attempt = 0; attempt < 3; ++attempt) {
        Bytes blob = vault.encrypt(cli.k_vault());
        try {
            uint32_t v = cli.put_vault(blob, cli.vault_version());
            std::cout << "Zsynchronizowano. Nowa wersja sejfu: " << v << "\n";
            return true;
        } catch (const ProtocolError& e) {
            if (e.code() == ERR_CONFLICT) {
                std::cout << "Konflikt wersji - pobieram wersję serwera i scalam...\n";
                Bytes srv_blob;
                if (cli.fetch_vault(srv_blob)) {
                    Vault srv = Vault::decrypt(srv_blob, cli.k_vault());
                    std::vector<std::string> conflicts;
                    int n = vault.merge_from(srv, conflicts);
                    if (n)
                        for (auto& c : conflicts)
                            std::cout << "  konflikt wpisu: " << c << " (wybrano nowszy)\n";
                }
                continue;  // ponów PUT z nową base_version
            }
            throw;
        }
    }
    std::cout << "Nie udało się zsynchronizować po 3 próbach.\n";
    return false;
}

}  // namespace

int main(int argc, char** argv) {
    Args a = parse_args(argc, argv);
    if (a.selftest) return selftest();

    Client cli(a.cfg);
    Vault vault;
    bool dirty = false;
    bool online = false;

    std::string login = read_line("Użytkownik: ");
    std::string password = read_password("Hasło główne: ");
    if (login.empty()) {
        std::cerr << "Brak nazwy użytkownika.\n";
        return 1;
    }
    cli.derive_keys(login, password);

    if (!a.offline) {
        try {
            cli.connect();
            std::string mode = read_line("Zaloguj (l) czy zarejestruj nowe konto (r)? [l] ");
            if (mode == "r" || mode == "R") {
                cli.register_account();
                std::cout << "Konto utworzone.\n";
                cli.login();
            } else {
                cli.login();
            }
            std::cout << "Zalogowano. Wersja sejfu na serwerze: " << cli.vault_version() << "\n";

            Bytes blob;
            if (cli.fetch_vault(blob)) {
                vault = Vault::decrypt(blob, cli.k_vault());
                save_cache(a.cache, login, cli.vault_id(), cli.vault_version(), blob);
                std::cout << "Pobrano sejf (" << vault.size() << " wpisów).\n";
            } else {
                std::cout << "Serwer nie ma jeszcze sejfu - zaczynamy pusty.\n";
            }
            online = true;
        } catch (const ProtocolError& e) {
            std::cerr << "Błąd protokołu: " << e.what() << "\n";
            if (e.code() == ERR_AUTH_FAILED) std::cerr << "Sprawdź login i hasło.\n";
            return 1;
        } catch (const std::exception& e) {
            std::cerr << "Brak połączenia z serwerem (" << e.what() << ").\n";
            std::cerr << "Przechodzę w tryb offline (tylko odczyt z lokalnej kopii).\n";
        }
    }

    if (!online) {
        // Tryb offline: odczyt z zaszyfrowanej kopii lokalnej (UC-03 offline).
        std::string c_login;
        Bytes c_vid, c_blob;
        uint32_t c_ver = 0;
        if (!load_cache(a.cache, c_login, c_vid, c_ver, c_blob)) {
            std::cerr << "Brak lokalnej kopii sejfu (" << a.cache << ").\n";
            return 1;
        }
        try {
            vault = Vault::decrypt(c_blob, cli.k_vault());
            std::cout << "Tryb offline: wczytano lokalną kopię (wersja " << c_ver << ", "
                      << vault.size() << " wpisów).\n";
        } catch (const std::exception&) {
            std::cerr << "Nie udało się odszyfrować lokalnej kopii (złe hasło?).\n";
            return 1;
        }
    }

    std::cout << "Wpisz 'help' aby zobaczyć komendy.\n";

    for (;;) {
        std::string line = read_line("secvault> ");
        if (std::cin.eof()) { std::cout << "\n"; break; }
        std::istringstream iss(line);
        std::string cmd, arg;
        iss >> cmd;
        std::getline(iss, arg);
        if (!arg.empty() && arg[0] == ' ') arg.erase(0, 1);

        if (cmd.empty()) continue;
        if (cmd == "help") { print_help(); }
        else if (cmd == "ls") {
            if (vault.size() == 0) std::cout << "(sejf pusty)\n";
            for (const auto& e : vault.entries())
                std::cout << "  " << e.id << "  " << e.service << "  (" << e.username << ")\n";
        }
        else if (cmd == "get") {
            Entry* e = vault.find_by_service(arg);
            if (!e) e = vault.find_by_id(arg);
            if (e) print_entry(*e, true);
            else std::cout << "Nie znaleziono wpisu: " << arg << "\n";
        }
        else if (cmd == "add") {
            std::string service = read_line("  serwis: ");
            std::string username = read_line("  login: ");
            std::string pw = read_password("  hasło: ");
            std::string notes = read_line("  notatka (opcjonalnie): ");
            vault.add(service, username, pw, notes);
            dirty = true;
            std::cout << "Dodano. Użyj 'sync' aby wysłać na serwer.\n";
        }
        else if (cmd == "edit") {
            Entry* e = vault.find_by_service(arg);
            if (!e) e = vault.find_by_id(arg);
            if (!e) { std::cout << "Nie znaleziono wpisu: " << arg << "\n"; continue; }
            std::cout << "(Enter = bez zmian)\n";
            std::string u = read_line("  login [" + e->username + "]: ");
            std::string pw = read_password("  nowe hasło: ");
            std::string n = read_line("  notatka [" + e->notes + "]: ");
            if (!u.empty()) e->username = u;
            if (!pw.empty()) e->password = pw;
            if (!n.empty()) e->notes = n;
            e->updated_at = static_cast<uint64_t>(time(nullptr));
            dirty = true;
            std::cout << "Zmieniono. Użyj 'sync'.\n";
        }
        else if (cmd == "rm" || cmd == "delete") {
            if (vault.remove(arg)) { dirty = true; std::cout << "Usunięto.\n"; }
            else std::cout << "Nie znaleziono wpisu: " << arg << "\n";
        }
        else if (cmd == "sync") {
            if (!online) { std::cout << "Tryb offline - synchronizacja niedostępna.\n"; continue; }
            try {
                if (do_sync(cli, vault)) {
                    dirty = false;
                    save_cache(a.cache, login, cli.vault_id(), cli.vault_version(),
                               vault.encrypt(cli.k_vault()));
                }
            } catch (const std::exception& e) {
                std::cout << "Błąd synchronizacji: " << e.what() << "\n";
            }
        }
        else if (cmd == "pull") {
            if (!online) { std::cout << "Tryb offline.\n"; continue; }
            try {
                cli.ensure_session();
                Bytes blob;
                if (cli.fetch_vault(blob)) {
                    Vault srv = Vault::decrypt(blob, cli.k_vault());
                    std::vector<std::string> conflicts;
                    vault.merge_from(srv, conflicts);
                    std::cout << "Pobrano i scalono (wersja " << cli.vault_version() << ").\n";
                } else std::cout << "Serwer nie ma sejfu.\n";
            } catch (const std::exception& e) {
                std::cout << "Błąd: " << e.what() << "\n";
            }
        }
        else if (cmd == "ping") {
            if (!online) { std::cout << "Tryb offline.\n"; continue; }
            try { cli.ensure_session(); std::cout << "PONG\n"; }
            catch (const std::exception& e) { std::cout << "Brak odpowiedzi: " << e.what() << "\n"; }
        }
        else if (cmd == "quit" || cmd == "exit") break;
        else std::cout << "Nieznana komenda: " << cmd << " (help)\n";
    }

    if (online && dirty) {
        std::cout << "Masz niezapisane zmiany - synchronizuję...\n";
        try { do_sync(cli, vault); } catch (const std::exception& e) {
            std::cout << "Nie udało się zsynchronizować: " << e.what() << "\n";
        }
    }
    if (online) cli.bye();
    std::cout << "Do widzenia.\n";
    return 0;
}
