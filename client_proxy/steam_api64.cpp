#define _CRT_SECURE_NO_WARNINGS 1
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")

// Configuration Defaults
static char g_server_ip[64] = "127.0.0.1";
static char g_server_port[16] = "8080";
static char g_player_name[64] = "Runner";
static uint64_t g_steam_id = 76561198000001001ULL;
static uint32_t g_app_id = 26136895;

static void LogMsg(const char* fmt, ...) {
    char buf[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    OutputDebugStringA(buf);
    
    FILE* fp = fopen("marathon_proxy.log", "a");
    if (fp) {
        fputs(buf, fp);
        fputc('\n', fp);
        fclose(fp);
    }
}

// ---------------------------------------------------------------------------
// Steam VTable & Interface Definitions
// ---------------------------------------------------------------------------
typedef void* (*GenericMethod)(void* self, ...);

static int64_t MethodReturnZero(void* self, ...) { return 0; }
static int64_t MethodReturnOne(void* self, ...) { return 1; }
static int64_t MethodReturnTrue(void* self, ...) { return 1; }

// Generic VTable container with 128 stubbed methods
struct InterfaceObject {
    void* vtable;
};

static void* g_generic_vtable[128];
static InterfaceObject g_generic_interface = { g_generic_vtable };

// ISteamUser023
static uint32_t SteamUser_GetHSteamUser(void* self) { return 1; }
static int SteamUser_BLoggedOn(void* self) { return 1; }
static uint64_t SteamUser_GetSteamID(void* self) { return g_steam_id; }
static uint32_t SteamUser_GetAuthSessionTicket(void* self, void* pTicket, int cbMaxTicket, uint32_t* pcbTicket, void* pNetIdentity) {
    LogMsg("[SteamAPI] GetAuthSessionTicket requested (max: %d)", cbMaxTicket);
    if (!pTicket || cbMaxTicket < 128) return 0;
    
    // Fill 128 bytes of deterministic ticket payload for marathon_server.py
    unsigned char* ticket = (unsigned char*)pTicket;
    for (int i = 0; i < 128; i++) {
        ticket[i] = (unsigned char)(0x55 ^ (i * 7));
    }
    if (pcbTicket) *pcbTicket = 128;
    return 1; // Ticket handle 1
}
static void SteamUser_CancelAuthTicket(void* self, uint32_t hAuthTicket) {
    LogMsg("[SteamAPI] CancelAuthTicket: %u", hAuthTicket);
}

static void* g_user_vtable[64];
static InterfaceObject g_user_interface = { g_user_vtable };

// ISteamUtils010
static int SteamUtils_GetConnectedUniverse(void* self) { return 1; } // Public universe
static const char* SteamUtils_GetIPCountry(void* self) { return "US"; }
static uint32_t SteamUtils_GetAppID(void* self) { return g_app_id; }
static uint32_t SteamUtils_GetServerRealTime(void* self) { return (uint32_t)time(NULL); }

static void* g_utils_vtable[64];
static InterfaceObject g_utils_interface = { g_utils_vtable };

// ISteamApps008
static int SteamApps_BIsSubscribed(void* self) { return 1; }
static int SteamApps_BIsSubscribedApp(void* self, uint32_t nAppID) { return 1; }
static const char* SteamApps_GetCurrentGameLanguage(void* self) { return "english"; }
static const char* SteamApps_GetAvailableGameLanguages(void* self) { return "english"; }

static void* g_apps_vtable[64];
static InterfaceObject g_apps_interface = { g_apps_vtable };

// ISteamFriends017
static const char* SteamFriends_GetPersonaName(void* self) { return g_player_name; }

static void* g_friends_vtable[80];
static InterfaceObject g_friends_interface = { g_friends_vtable };

static void InitInterfaceTables() {
    for (int i = 0; i < 128; i++) g_generic_vtable[i] = (void*)MethodReturnZero;
    for (int i = 0; i < 64; i++) g_user_vtable[i] = (void*)MethodReturnZero;
    for (int i = 0; i < 64; i++) g_utils_vtable[i] = (void*)MethodReturnZero;
    for (int i = 0; i < 64; i++) g_apps_vtable[i] = (void*)MethodReturnZero;
    for (int i = 0; i < 80; i++) g_friends_vtable[i] = (void*)MethodReturnZero;

    // User023 slots
    g_user_vtable[0] = (void*)SteamUser_GetHSteamUser;
    g_user_vtable[1] = (void*)SteamUser_BLoggedOn;
    g_user_vtable[2] = (void*)SteamUser_GetSteamID;
    g_user_vtable[13] = (void*)SteamUser_GetAuthSessionTicket;
    g_user_vtable[16] = (void*)SteamUser_CancelAuthTicket;

    // Utils010 slots
    g_utils_vtable[2] = (void*)SteamUtils_GetConnectedUniverse;
    g_utils_vtable[4] = (void*)SteamUtils_GetIPCountry;
    g_utils_vtable[9] = (void*)SteamUtils_GetAppID;
    g_utils_vtable[11] = (void*)SteamUtils_GetServerRealTime;

    // Apps008 slots
    g_apps_vtable[0] = (void*)SteamApps_BIsSubscribed;
    g_apps_vtable[4] = (void*)SteamApps_GetCurrentGameLanguage;
    g_apps_vtable[5] = (void*)SteamApps_GetAvailableGameLanguages;
    g_apps_vtable[6] = (void*)SteamApps_BIsSubscribedApp;

    // Friends017 slots
    g_friends_vtable[0] = (void*)SteamFriends_GetPersonaName;
}

// ---------------------------------------------------------------------------
// Exported SteamAPI Functions
// ---------------------------------------------------------------------------
extern "C" {

__declspec(dllexport) bool __cdecl SteamAPI_Init() {
    LogMsg("[SteamAPI] SteamAPI_Init called -> SUCCESS");
    return true;
}

__declspec(dllexport) void __cdecl SteamAPI_Shutdown() {
    LogMsg("[SteamAPI] SteamAPI_Shutdown called");
}

__declspec(dllexport) bool __cdecl SteamAPI_RestartAppIfNecessary(uint32_t unOwnAppID) {
    LogMsg("[SteamAPI] SteamAPI_RestartAppIfNecessary(%u) called -> FALSE (no restart needed)", unOwnAppID);
    return false; // Crucial: false tells the game it is running properly
}

__declspec(dllexport) bool __cdecl SteamAPI_IsSteamRunning() {
    return true;
}

__declspec(dllexport) uint32_t __cdecl SteamAPI_GetHSteamUser() {
    return 1;
}

__declspec(dllexport) uint32_t __cdecl SteamAPI_GetHSteamPipe() {
    return 1;
}

__declspec(dllexport) void __cdecl SteamAPI_RegisterCallback(void* pCallback, int iCallback) {
    LogMsg("[SteamAPI] RegisterCallback: id=%d", iCallback);
}

__declspec(dllexport) void __cdecl SteamAPI_UnregisterCallback(void* pCallback) {
}

__declspec(dllexport) void __cdecl SteamAPI_RegisterCallResult(void* pCallback, uint64_t hAPICall) {
    LogMsg("[SteamAPI] RegisterCallResult: call=%llu", hAPICall);
}

__declspec(dllexport) void __cdecl SteamAPI_UnregisterCallResult(void* pCallback, uint64_t hAPICall) {
}

__declspec(dllexport) void __cdecl SteamAPI_RunCallbacks() {
}

__declspec(dllexport) void* __cdecl SteamInternal_CreateInterface(const char* ver) {
    LogMsg("[SteamAPI] SteamInternal_CreateInterface: %s", ver ? ver : "null");
    return &g_generic_interface;
}

__declspec(dllexport) void* __cdecl SteamInternal_FindOrCreateUserInterface(uint32_t hUser, const char* ver) {
    LogMsg("[SteamAPI] FindOrCreateUserInterface: user=%u, ver=%s", hUser, ver ? ver : "null");
    if (!ver) return &g_generic_interface;
    if (strstr(ver, "SteamUser")) return &g_user_interface;
    if (strstr(ver, "SteamUtils")) return &g_utils_interface;
    if (strstr(ver, "SteamApps")) return &g_apps_interface;
    if (strstr(ver, "SteamFriends")) return &g_friends_interface;
    return &g_generic_interface;
}

__declspec(dllexport) void* __cdecl SteamInternal_ContextInit(void* pCtx) {
    return pCtx;
}

__declspec(dllexport) bool __cdecl SteamInternal_SteamAPI_Init(const char* pszExplicitOptIn, void* pError) {
    LogMsg("[SteamAPI] SteamInternal_SteamAPI_Init called -> SUCCESS");
    return true;
}

} // extern "C"

// ---------------------------------------------------------------------------
// Network Egress Hooking (IAT Hook for WS2_32.dll!getaddrinfo)
// ---------------------------------------------------------------------------
typedef int (WSAAPI *getaddrinfo_t)(
    PCSTR pNodeName,
    PCSTR pServiceName,
    const ADDRINFOA *pHints,
    PADDRINFOA *ppResult
);

static getaddrinfo_t g_real_getaddrinfo = NULL;

static int WSAAPI Hook_getaddrinfo(
    PCSTR pNodeName,
    PCSTR pServiceName,
    const ADDRINFOA *pHints,
    PADDRINFOA *ppResult
) {
    PCSTR node = pNodeName;
    PCSTR service = pServiceName;

    if (pNodeName && (strstr(pNodeName, "deadorbit.net") || strstr(pNodeName, "bungie.net"))) {
        LogMsg("[Egress] Intercepted DNS query for '%s' -> Redirecting to '%s:%s'",
               pNodeName, g_server_ip, g_server_port);
        node = g_server_ip;
        if (pServiceName && (strcmp(pServiceName, "443") == 0 || strcmp(pServiceName, "https") == 0)) {
            service = g_server_port;
        }
    }

    return g_real_getaddrinfo(node, service, pHints, ppResult);
}

static void InstallIATHook() {
    HMODULE hExe = GetModuleHandleA(NULL);
    if (!hExe) return;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hExe;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((uint8_t*)hExe + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    IMAGE_DATA_DIRECTORY importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress == 0 || importDir.Size == 0) return;

    PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)((uint8_t*)hExe + importDir.VirtualAddress);

    HMODULE hWs2 = GetModuleHandleA("WS2_32.dll");
    if (!hWs2) hWs2 = LoadLibraryA("WS2_32.dll");
    if (!hWs2) return;

    void* targetFunc = (void*)GetProcAddress(hWs2, "getaddrinfo");
    if (!targetFunc) return;
    g_real_getaddrinfo = (getaddrinfo_t)targetFunc;

    while (pImport->Name) {
        const char* modName = (const char*)((uint8_t*)hExe + pImport->Name);
        if (_stricmp(modName, "WS2_32.dll") == 0) {
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((uint8_t*)hExe + pImport->FirstThunk);
            while (thunk->u1.Function) {
                if ((void*)thunk->u1.Function == targetFunc) {
                    DWORD oldProtect;
                    if (VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProtect)) {
                        thunk->u1.Function = (uintptr_t)Hook_getaddrinfo;
                        VirtualProtect(&thunk->u1.Function, sizeof(void*), oldProtect, &oldProtect);
                        LogMsg("[Egress] Successfully installed IAT hook for WS2_32!getaddrinfo");
                        return;
                    }
                }
                thunk++;
            }
        }
        pImport++;
    }
}

static void LoadConfig() {
    char iniPath[MAX_PATH];
    GetModuleFileNameA(NULL, iniPath, sizeof(iniPath));
    char* lastSlash = strrchr(iniPath, '\\');
    if (lastSlash) *(lastSlash + 1) = '\0';
    strcat(iniPath, "marathon_client.ini");

    GetPrivateProfileStringA("Marathon", "ServerIP", "127.0.0.1", g_server_ip, sizeof(g_server_ip), iniPath);
    GetPrivateProfileStringA("Marathon", "ServerPort", "8080", g_server_port, sizeof(g_server_port), iniPath);
    GetPrivateProfileStringA("Marathon", "PlayerName", "Runner", g_player_name, sizeof(g_player_name), iniPath);
    
    char idStr[32] = "76561198000001001";
    GetPrivateProfileStringA("Marathon", "SteamID", idStr, idStr, sizeof(idStr), iniPath);
    g_steam_id = _strtoui64(idStr, NULL, 10);

    LogMsg("[Config] Loaded marathon_client.ini -> IP: %s, Port: %s, Player: %s, SteamID: %llu",
           g_server_ip, g_server_port, g_player_name, g_steam_id);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        LogMsg("==================================================");
        LogMsg(" Marathon Standalone Client Proxy (Project Dawn)");
        LogMsg(" Target Build: 26136895 (Cryo Archive Vault Breaker)");
        LogMsg("==================================================");
        LoadConfig();
        InitInterfaceTables();
        InstallIATHook();
    }
    return TRUE;
}
