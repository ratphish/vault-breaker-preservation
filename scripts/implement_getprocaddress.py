import os

filepath = r'D:\vault-breaker-preservation\client_proxy\steam_api64.cpp'
with open(filepath, 'r', encoding='utf-8') as f:
    code = f.read()

target = 'static FARPROC WINAPI Hook_GetProcAddress(HMODULE hModule, LPCSTR lpProcName);'

impl = '''static FARPROC WINAPI Hook_GetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    if (!g_real_GetProcAddress) {
        HMODULE hK32 = GetModuleHandleA("KERNEL32.dll");
        if (hK32) g_real_GetProcAddress = (GetProcAddress_t)GetProcAddress(hK32, "GetProcAddress");
    }
    FARPROC realProc = g_real_GetProcAddress ? g_real_GetProcAddress(hModule, lpProcName) : NULL;
    if ((uintptr_t)lpProcName > 0xFFFF) {
        if (strcmp(lpProcName, "connect") == 0) {
            LogMsg("[GetProcAddress] Dynamic lookup: connect -> hooked");
            return (FARPROC)Hook_connect;
        } else if (strcmp(lpProcName, "WSAConnect") == 0) {
            LogMsg("[GetProcAddress] Dynamic lookup: WSAConnect -> hooked");
            return (FARPROC)Hook_WSAConnect;
        } else if (strcmp(lpProcName, "getaddrinfo") == 0) {
            LogMsg("[GetProcAddress] Dynamic lookup: getaddrinfo -> hooked");
            return (FARPROC)Hook_getaddrinfo;
        } else if (strcmp(lpProcName, "GetAddrInfoW") == 0) {
            LogMsg("[GetProcAddress] Dynamic lookup: GetAddrInfoW -> hooked");
            return (FARPROC)Hook_GetAddrInfoW;
        } else if (strcmp(lpProcName, "GetAddrInfoExW") == 0) {
            LogMsg("[GetProcAddress] Dynamic lookup: GetAddrInfoExW -> hooked");
            return (FARPROC)Hook_GetAddrInfoExW;
        } else if (strcmp(lpProcName, "CertVerifyCertificateChainPolicy") == 0) {
            LogMsg("[GetProcAddress] Dynamic lookup: CertVerifyCertificateChainPolicy -> hooked");
            return (FARPROC)Hook_CertVerifyCertificateChainPolicy;
        }
    } else {
        uint16_t ord = (uint16_t)((uintptr_t)lpProcName & 0xFFFF);
        if (ord == 4) {
            LogMsg("[GetProcAddress] Dynamic lookup: ord(4) -> connect hooked");
            return (FARPROC)Hook_connect;
        }
    }
    return realProc;
}'''

assert target in code, "Hook_GetProcAddress declaration not found"
code = code.replace(target, impl)

with open(filepath, 'w', encoding='utf-8') as f:
    f.write(code)
print('Implemented Hook_GetProcAddress successfully!')
