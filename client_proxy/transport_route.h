#pragma once
#include <stdint.h>

// ServerPort is the TLS fallback. Plain HTTP must never be sent there merely
// because the same proxy redirects both protocols.
static inline uint16_t MarathonRedirectPort(uint16_t original, uint16_t tls_port) {
    switch (original) {
        case 80: return 80;
        case 443: case 8080: return tls_port;
        default: return original;
    }
}

static inline bool MarathonRedirectableTcpPort(uint16_t port) {
    return port == 80 || port == 443 || port == 8080 || port == 7777 || port == 7505;
}

// Input is in host byte order. All of 127/8 is loopback, not just 127.0.0.1.
static inline bool MarathonLoopbackIPv4(uint32_t host_address) {
    return (host_address & 0xff000000u) == 0x7f000000u;
}

static inline bool MarathonLoopbackIPv6(const unsigned char* address) {
    bool first_ten_zero = true;
    for (int index = 0; index < 10; ++index) first_ten_zero &= address[index] == 0;
    if (!first_ten_zero) return false;
    if (address[10] == 0xff && address[11] == 0xff) return address[12] == 127;
    return address[10] == 0 && address[11] == 0 && address[12] == 0 &&
           address[13] == 0 && address[14] == 0 && address[15] == 1;
}
