// socket.hpp — cross-platform socket utilities.
//
// Thin wrappers over Winsock2 (Windows) and POSIX sockets (Linux).
// Handles initialization, address parsing, raw socket creation,
// and non-blocking connect with timeout.

#pragma once

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <sys/select.h>
    #include <netinet/in.h>
    #include <netinet/ip.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <errno.h>
    using SOCKET = int;
    inline constexpr int INVALID_SOCKET = -1;
    inline constexpr int SOCKET_ERROR = -1;
    inline int closesocket(int fd) { return close(fd); }
#endif

#include <string>
#include <string_view>
#include <cstdint>
#include <chrono>

namespace sock {

// --- one-time WSA startup (Windows) or no-op (Linux) ---
bool initialize();
void cleanup();

// --- resolve hostname → IPv4 address ---
// Returns 0 on failure.
uint32_t resolve_host(std::string_view host);

// --- create sockets ---
SOCKET create_tcp();       // SOCK_STREAM
SOCKET create_udp();       // SOCK_DGRAM
SOCKET create_raw_tcp();   // SOCK_RAW + IPPROTO_TCP (needs admin/root)

// --- non-blocking connect with timeout ---
// Returns true if connected within `timeout_ms` milliseconds.
bool connect_timeout(SOCKET sock, uint32_t ip, uint16_t port, int timeout_ms);

// --- set socket options ---
bool set_nonblocking(SOCKET sock);
bool set_reuse_addr(SOCKET sock);
bool set_ttl(SOCKET sock, int ttl);

// --- send full buffer (handles short writes) ---
int send_all(SOCKET sock, const void* data, size_t len);

// --- recv with timeout ---
int recv_timeout(SOCKET sock, void* buf, size_t len, int timeout_ms);

// --- random helpers ---
uint32_t random_ip();     // random global IPv4 (excludes RFC1918, loopback, multicast)
uint16_t random_port();   // random high port (1024–65535)
void     random_bytes(void* buf, size_t len);

} // namespace sock
