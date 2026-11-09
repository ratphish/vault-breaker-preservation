#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#pragma comment(lib, "bcrypt.lib")

void ComputeSHA256(const void* data, size_t len, char* hexOut) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    UCHAR hash[32];
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) == 0) {
        if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) == 0) {
            BCryptHashData(hHash, (PUCHAR)data, (ULONG)len, 0);
            BCryptFinishHash(hHash, hash, sizeof(hash), 0);
            BCryptDestroyHash(hHash);
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    for (int i = 0; i < 32; i++) {
        sprintf(hexOut + (i * 2), "%02x", hash[i]);
    }
    hexOut[64] = '\0';
}

int main() {
    const char* str = "Hello Tiger Engine SignOn";
    char hex[65];
    ComputeSHA256(str, strlen(str), hex);
    printf("BCrypt SHA256: %s\n", hex);
    return 0;
}
