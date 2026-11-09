#include <stdio.h>
#include <stdint.h>
#include <string.h>

static uint32_t CalculateCRC32(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & (-(int)(crc & 1)));
        }
    }
    return ~crc;
}

static int WriteVarint(uint8_t* dst, uint64_t val) {
    int idx = 0;
    while (val >= 0x80) {
        dst[idx++] = (uint8_t)((val & 0x7F) | 0x80);
        val >>= 7;
    }
    dst[idx++] = (uint8_t)(val & 0x7F);
    return idx;
}

int main() {
    uint8_t inner[128];
    uint8_t data[24] = {
        0xf3,0xd3,0x22,0xe0,0x86,0xb3,0x39,0x6e,
        0xd6,0x94,0xbd,0xb0,0x7c,0x51,0xf6,0x05,
        0xb3,0x80,0x62,0x3c,0xc7,0x4a,0x31,0x4b
    };
    memcpy(inner, data, 24);
    for (int i = 24; i < 128; i++) {
        inner[i] = (uint8_t)((i * 7) & 0xFF);
    }
    uint32_t crc = CalculateCRC32(inner, 128);
    printf("CRC32: %u (0x%08X)\n", crc, crc);

    uint8_t proto[256];
    int p = 0;
    // Field 1: ticket_version_no = 1
    proto[p++] = (1 << 3) | 0;
    p += WriteVarint(&proto[p], 1);

    // Field 2: crc_encryptedticket
    proto[p++] = (2 << 3) | 0;
    p += WriteVarint(&proto[p], crc);

    // Field 3: cb_encrypteduserdata
    proto[p++] = (3 << 3) | 0;
    p += WriteVarint(&proto[p], 24);

    // Field 4: cb_encrypted_appownershipticket
    proto[p++] = (4 << 3) | 0;
    p += WriteVarint(&proto[p], 128 - 24);

    // Field 5: encrypted_ticket
    proto[p++] = (5 << 3) | 2;
    p += WriteVarint(&proto[p], 128);
    memcpy(&proto[p], inner, 128);
    p += 128;

    printf("Total proto size: %d\n", p);
    printf("First 20 bytes: ");
    for (int i = 0; i < 20; i++) printf("%02x ", proto[i]);
    printf("\n");
    return 0;
}
