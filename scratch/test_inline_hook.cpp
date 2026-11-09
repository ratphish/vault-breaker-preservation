#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdint.h>

#pragma comment(lib, "ws2_32.lib")

static bool InstallInlineHook(void* pTarget, void* pHook, size_t stolenLen, void** ppTrampoline) {
    if (!pTarget || !pHook || stolenLen < 14) return false;

    uint8_t* tramp = (uint8_t*)VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!tramp) return false;

    // Copy stolen bytes
    memcpy(tramp, pTarget, stolenLen);

    // Jump back to target + stolenLen
    tramp[stolenLen + 0] = 0xFF;
    tramp[stolenLen + 1] = 0x25;
    tramp[stolenLen + 2] = 0x00;
    tramp[stolenLen + 3] = 0x00;
    tramp[stolenLen + 4] = 0x00;
    tramp[stolenLen + 5] = 0x00;
    *(uint64_t*)(&tramp[stolenLen + 6]) = (uint64_t)((uint8_t*)pTarget + stolenLen);

    *ppTrampoline = tramp;

    // Patch target
    DWORD oldProtect;
    if (!VirtualProtect(pTarget, stolenLen, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }

    uint8_t* targetBytes = (uint8_t*)pTarget;
    targetBytes[0] = 0xFF;
    targetBytes[1] = 0x25;
    targetBytes[2] = 0x00;
    targetBytes[3] = 0x00;
    targetBytes[4] = 0x00;
    targetBytes[5] = 0x00;
    *(uint64_t*)(&targetBytes[6]) = (uint64_t)pHook;

    if (stolenLen > 14) {
        memset(&targetBytes[14], 0x90, stolenLen - 14);
    }

    VirtualProtect(pTarget, stolenLen, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), pTarget, stolenLen);
    FlushInstructionCache(GetCurrentProcess(), tramp, stolenLen + 14);

    return true;
}

typedef int (WSAAPI *connect_t)(SOCKET s, const struct sockaddr* name, int namelen);
static connect_t g_real_connect = NULL;
static bool g_hook_called = false;

static int WSAAPI Test_Hook_connect(SOCKET s, const struct sockaddr* name, int namelen) {
    printf("[HOOK] Test_Hook_connect called successfully!\n");
    g_hook_called = true;
    return g_real_connect(s, name, namelen);
}

int main() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    HMODULE hWs2 = GetModuleHandleA("ws2_32.dll");
    void* pConnect = (void*)GetProcAddress(hWs2, "connect");
    printf("[*] Original ws2_32!connect at %p\n", pConnect);

    if (!InstallInlineHook(pConnect, (void*)Test_Hook_connect, 16, (void**)&g_real_connect)) {
        printf("[-] Failed to install hook\n");
        return 1;
    }
    printf("[+] Inline hook installed! Trampoline at %p\n", g_real_connect);

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(9999);
    sin.sin_addr.s_addr = inet_addr("127.0.0.1");

    printf("[*] Calling connect()...\n");
    int res = connect(s, (struct sockaddr*)&sin, sizeof(sin));
    printf("[*] connect() returned %d (LastError=%d)\n", res, WSAGetLastError());
    closesocket(s);
    WSACleanup();

    if (g_hook_called) {
        printf("[SUCCESS] Inline hook verified working!\n");
        return 0;
    } else {
        printf("[FAIL] Hook was not called!\n");
        return 2;
    }
}
