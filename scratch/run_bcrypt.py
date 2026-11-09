import subprocess

code = r"""#include <windows.h>
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
"""

with open(r'd:\vault-breaker-preservation\scratch\test_bcrypt.cpp', 'w') as f:
    f.write(code)

batch = r"""@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cl /nologo /EHsc d:\vault-breaker-preservation\scratch\test_bcrypt.cpp /Fe:d:\vault-breaker-preservation\scratch\test_bcrypt.exe /Fo:d:\vault-breaker-preservation\scratch\test_bcrypt.obj bcrypt.lib
d:\vault-breaker-preservation\scratch\test_bcrypt.exe
"""
with open(r'd:\vault-breaker-preservation\scratch\run_bcrypt.bat', 'w') as f:
    f.write(batch)

res = subprocess.run(r'cmd.exe /c d:\vault-breaker-preservation\scratch\run_bcrypt.bat', capture_output=True, text=True)
print("STDOUT:\n", res.stdout)
print("STDERR:\n", res.stderr)
