// socket.cpp — cross-platform socket utilities implementation.

#include "socket.hpp"
#include <random>
#include <cstring>
#include <thread>

#ifdef _WIN32
    #include <mstcpip.h>   // for TCP keepalive
#else
    #include <sys/time.h>
    #include <sys/ioctl.h>
#endif

namespace sock {

// --- PRNG (Mersenne Twister, seeded once) ---
static std::mt19937& rng() {
    static std::mt19937 r(std::random_device{}() ^
        static_cast<uint32_t>(std::chrono::steady_clock::now().time_since_epoch().count()));
    return r;
}

// --- initialization ---

bool initialize() {
#ifdef _WIN32
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
#else
    return true;
#endif
}

void cleanup() {
#ifdef _WIN32
    WSACleanup();
#endif
}

// --- DNS resolution ---

uint32_t resolve_host(std::string_view host) {
    std::string host_str(host);
    struct addrinfo hints{}, *result = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host_str.c_str(), nullptr, &hints, &result) != 0) {
        return 0;
    }

    uint32_t ip = 0;
    if (result && result->ai_addr) {
        auto* in = reinterpret_cast<struct sockaddr_in*>(result->ai_addr);
        ip = ntohl(in->sin_addr.s_addr);
    }
    freeaddrinfo(result);
    return ip;
}

// --- socket creation ---

SOCKET create_tcp() {
    return socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
}

SOCKET create_udp() {
    return socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
}

SOCKET create_raw_tcp() {
    // Requires admin/root. On Windows, raw sockets are restricted
    // since XP SP2 — use WinPCap/Npcap or a kernel driver instead.
    SOCKET s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (s != INVALID_SOCKET) {
        // Tell the kernel we're building our own IP header.
        int on = 1;
#ifdef _WIN32
        // Windows: raw sockets can't send TCP directly without a driver.
        // This socket creation is here for Linux compatibility.
#else
        setsockopt(s, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
#endif
    }
    return s;
}

// --- non-blocking connect ---

bool set_nonblocking(SOCKET sock) {
#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(sock, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(sock, F_GETFL, 0);
    return fcntl(sock, F_SETFL, flags | O_NONBLOCK) != -1;
#endif
}

bool set_reuse_addr(SOCKET sock) {
    int on = 1;
    return setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
        reinterpret_cast<const char*>(&on), sizeof(on)) == 0;
}

bool set_ttl(SOCKET sock, int ttl) {
    return setsockopt(sock, IPPROTO_IP, IP_TTL,
        reinterpret_cast<const char*>(&ttl), sizeof(ttl)) == 0;
}

bool connect_timeout(SOCKET sock, uint32_t ip, uint16_t port, int timeout_ms) {
    set_nonblocking(sock);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(ip);
    addr.sin_port = htons(port);

    connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));

    // Wait for the socket to become writable (connect complete).
    fd_set write_set, err_set;
    FD_ZERO(&write_set);
    FD_ZERO(&err_set);
    FD_SET(sock, &write_set);
    FD_SET(sock, &err_set);

    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int ret = select(static_cast<int>(sock) + 1,
        nullptr, &write_set, &err_set, &tv);

    if (ret <= 0) {
        return false; // timeout or error
    }

    // Check if connect succeeded.
    if (FD_ISSET(sock, &err_set)) {
        return false;
    }

    int error = 0;
    socklen_t len = sizeof(error);
    getsockopt(sock, SOL_SOCKET, SO_ERROR,
        reinterpret_cast<char*>(&error), &len);
    return error == 0;
}

// --- send/recv ---

int send_all(SOCKET sock, const void* data, size_t len) {
    size_t sent = 0;
    const char* ptr = static_cast<const char*>(data);

    while (sent < len) {
        int n = send(sock, ptr + sent, static_cast<int>(len - sent), 0);
        if (n <= 0) {
            return n; // error or closed
        }
        sent += n;
    }
    return static_cast<int>(sent);
}

int recv_timeout(SOCKET sock, void* buf, size_t len, int timeout_ms) {
    fd_set read_set;
    FD_ZERO(&read_set);
    FD_SET(sock, &read_set);

    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int ret = select(static_cast<int>(sock) + 1, &read_set, nullptr, nullptr, &tv);
    if (ret <= 0) {
        return ret; // 0 = timeout, -1 = error
    }

    return recv(sock, static_cast<char*>(buf), static_cast<int>(len), 0);
}

// --- randomization ---

uint32_t random_ip() {
    // Generate a random global IPv4 address.
    // Excludes: 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16,
    //           172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4
    std::uniform_int_distribution<uint32_t> dist(0, 0xFFFFFFFF);
    uint32_t ip;
    for (int attempts = 0; attempts < 100; ++attempts) {
        ip = dist(rng());
        uint8_t b1 = (ip >> 24) & 0xFF;
        uint8_t b2 = (ip >> 16) & 0xFF;

        // Reject bogon ranges.
        if (b1 == 0)    continue;  // 0.0.0.0/8
        if (b1 == 10)   continue;  // 10.0.0.0/8
        if (b1 == 127)  continue;  // 127.0.0.0/8
        if (b1 >= 224)  continue;  // multicast + reserved
        if (b1 == 169 && b2 == 254) continue;  // link-local
        if (b1 == 172 && (b2 >= 16 && b2 <= 31)) continue;  // 172.16.0.0/12
        if (b1 == 192 && b2 == 168) continue;  // 192.168.0.0/16

        // Exclude DoD ranges (per Mirai's scanner) — optional, remove if you want.
        // if (b1 == 6)   continue;  // 6.0.0.0/8 (Army)
        // if (b1 == 7)   continue;  // 7.0.0.0/8 (DoD)
        // if (b1 == 11)  continue;  // 11.0.0.0/8 (DoD)
        // if (b1 >= 21 && b1 <= 22) continue; // 21/8, 22/8 (DoD)
        // if (b1 == 26)  continue;  // ...
        // if (b1 >= 28 && b1 <= 30) continue;

        return ip;
    }
    return 0x08080808; // fallback: 8.8.8.8
}

uint16_t random_port() {
    std::uniform_int_distribution<uint16_t> dist(1024, 65535);
    return dist(rng());
}

void random_bytes(void* buf, size_t len) {
    std::uniform_int_distribution<int> dist(0, 255);
    auto* ptr = static_cast<uint8_t*>(buf);
    for (size_t i = 0; i < len; ++i) {
        ptr[i] = static_cast<uint8_t>(dist(rng()));
    }
}

} // namespace sock
