#define _CRT_SECURE_NO_WARNINGS 1
#define _WINSOCK_DEPRECATED_NO_WARNINGS 1
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wincrypt.h>
#include <winhttp.h>
#include <intrin.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#pragma intrinsic(_ReturnAddress)
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "winhttp.lib")
// Configuration Defaults

static char g_server_ip[64] = "127.0.0.1";
static char g_server_port[16] = "8080";
static char g_player_name[64] = "Runner";
static uint64_t g_steam_id = 76561198000001001ULL;
static uint32_t g_app_id = 3065800; // Marathon Steam AppID
static char g_log_path[MAX_PATH] = {0};
static void InitLogPath(HINSTANCE hinstDLL) {
    char path[MAX_PATH] = {0};
    if (GetModuleFileNameA(hinstDLL, path, MAX_PATH)) {
        char* lastSlash = strrchr(path, '\\');
        if (lastSlash) {
            *lastSlash = '\0';
            // If inside bin\x64, navigate up to game root

            char* binPos = strstr(path, "\\bin\\x64");
            if (binPos) *binPos = '\0';
            snprintf(g_log_path, sizeof(g_log_path), "%s\\marathon_proxy.log", path);
        }

    }

    if (!g_log_path[0]) {
        strcpy(g_log_path, "D:\\Marathon-live\\marathon_proxy.log");
    }

}

static void LogMsg(const char* fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    OutputDebugStringA(buf);
    FILE* fp = fopen(g_log_path[0] ? g_log_path : "marathon_proxy.log", "a");
    if (fp) {
        fputs(buf, fp);
        fputc('\n', fp);
        fflush(fp); // Flush immediately to capture any crash
        fclose(fp);
    }

}

// Case-insensitive substring search

static void LogCallerInfo(const char* prefix, void* caller) {
    DWORD tid = GetCurrentThreadId();
    HMODULE hMod = NULL;
    char modName[MAX_PATH] = "Unknown";
    uintptr_t rva = 0;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)caller, &hMod) && hMod) {
        char fullPath[MAX_PATH];
        if (GetModuleFileNameA(hMod, fullPath, sizeof(fullPath))) {
            const char* slash = strrchr(fullPath, '\\');
            strncpy(modName, slash ? slash + 1 : fullPath, sizeof(modName) - 1);
        }
        rva = (uintptr_t)caller - (uintptr_t)hMod;
    }
    LogMsg("[%s] [TID:%u] from %s+0x%llX (addr=%p)", prefix, tid, modName, (unsigned long long)rva, caller);
}

static bool CaseInsensitiveContains(const char* haystack, const char* needle) {
    if (!haystack || !needle) return false;
    for (; *haystack; ++haystack) {
        const char* h = haystack;
        const char* n = needle;
        while (*h && *n && (tolower((unsigned char)*h) == tolower((unsigned char)*n))) {
            h++;
            n++;
        }

        if (!*n) return true;
    }

    return false;
}

// ---------------------------------------------------------------------------

// Steam VTable & Interface Definitions

// ---------------------------------------------------------------------------

struct InterfaceObject {
    void* vtable;
};
// Generic fallback stub

static int64_t MethodReturnZero(void* self, ...) {
    void* caller = _ReturnAddress();
    LogMsg("[VTABLE-STUB] MethodReturnZero called (self=%p, caller=%p)", self, caller);
    return 0;
}

static int64_t MethodReturnOne(void* self, ...) {
    void* caller = _ReturnAddress();
    LogMsg("[VTABLE-STUB] MethodReturnOne called (self=%p, caller=%p)", self, caller);
    return 1;
}

static void* g_generic_vtable[128];
static InterfaceObject g_generic_interface = { g_generic_vtable };
static void* g_user_vtable[64];
static InterfaceObject g_user_interface = { g_user_vtable };
static void* g_utils_vtable[64];
static InterfaceObject g_utils_interface = { g_utils_vtable };
static void* g_apps_vtable[64];
static InterfaceObject g_apps_interface = { g_apps_vtable };
static void* g_friends_vtable[80];
static InterfaceObject g_friends_interface = { g_friends_vtable };
static void* g_userstats_vtable[64];
static InterfaceObject g_userstats_interface = { g_userstats_vtable };
static void* g_input_vtable[64];
static InterfaceObject g_input_interface = { g_input_vtable };
// ISteamUser023

static uint32_t SteamUser_GetHSteamUser(void* self) { 
    LogMsg("[SteamUser] GetHSteamUser called");
    return 1; 
}

static int SteamUser_BLoggedOn(void* self) { 
    void* caller = _ReturnAddress();
    LogCallerInfo("SteamUser-BLoggedOn", caller);
    LogMsg("[SteamUser] BLoggedOn called -> 1");
    return 1; 
}

static uint64_t g_steam_id_storage = 76561198000001001ULL;
static void* SteamUser_GetSteamID(void* self, void* pOutResult) { 
    LogMsg("[SteamUser] GetSteamID(self=%p, pOut=%p) called -> %llu", self, pOutResult, g_steam_id);
    g_steam_id_storage = g_steam_id;
    if (pOutResult && pOutResult != &g_user_interface) {
        *(uint64_t*)pOutResult = g_steam_id;
        return pOutResult;
    }

    if (self && self != &g_user_interface) {
        *(uint64_t*)self = g_steam_id;
        return self;
    }

    return &g_steam_id_storage;
}

static uint32_t SteamUser_GetAuthSessionTicket(void* self, void* pTicket, int cbMaxTicket, uint32_t* pcbTicket, void* pNetIdentity) {
    LogMsg("[SteamUser] GetAuthSessionTicket requested (max: %d)", cbMaxTicket);
    if (!pTicket || cbMaxTicket < 128) return 0;
    unsigned char* ticket = (unsigned char*)pTicket;
    for (int i = 0; i < 128; i++) {
        ticket[i] = (unsigned char)(0x55 ^ (i * 7));
    }

    if (pcbTicket) *pcbTicket = 128;
    LogMsg("[SteamUser] Generated mock auth ticket (len=128, steam_id=%llu)", g_steam_id);
    return 1; // Ticket handle 1
}

static void SteamUser_CancelAuthTicket(void* self, uint32_t hAuthTicket) {
    LogMsg("[SteamUser] CancelAuthTicket: %u", hAuthTicket);
}

static uint64_t g_next_api_call = 1;
static uint64_t SteamUser_RequestEncryptedAppTicket(void* self, void* pDataToInclude, int cbDataToInclude) {
    void* caller = _ReturnAddress();
    LogCallerInfo("SteamUser-RequestEncryptedAppTicket", caller);
    uint64_t callId = g_next_api_call++;
    LogMsg("[SteamUser] RequestEncryptedAppTicket called (pDataToInclude=%p, cb=%d) -> handle %llu",
           pDataToInclude, cbDataToInclude, (unsigned long long)callId);
    return callId;
}

static int SteamUser_GetEncryptedAppTicket(void* self, void* pTicket, int cbMaxTicket, uint32_t* pcbTicket) {
    void* caller = _ReturnAddress();
    LogCallerInfo("SteamUser-GetEncryptedAppTicket", caller);
    LogMsg("[SteamUser] GetEncryptedAppTicket called (pTicket=%p, max=%d, pcbTicket=%p)", pTicket, cbMaxTicket, pcbTicket);
    FILE* fpCaller = fopen("D:/Marathon-live/mem_ticket_caller.bin", "wb");
    if (fpCaller) {
        BYTE* s = ((uintptr_t)caller >= 64) ? ((BYTE*)caller - 64) : (BYTE*)caller;
        fwrite(s, 1, 256, fpCaller);
        fclose(fpCaller);
        LogMsg("[SteamUser] Dumped 256 bytes around caller (%p) to mem_ticket_caller.bin", caller);
    }
    if (!pTicket || cbMaxTicket <= 0) {
        if (pcbTicket) *pcbTicket = 128;
        return 0;
    }

    int len = cbMaxTicket < 128 ? cbMaxTicket : 128;
    unsigned char* ticket = (unsigned char*)pTicket;
    for (int i = 0; i < len; i++) {
        ticket[i] = (unsigned char)(0xAA ^ (i * 13));
    }

    if (pcbTicket) *pcbTicket = len;
    LogMsg("[SteamUser] Generated mock encrypted app ticket (len=%d) -> returning 1 (true)", len);
    return 1;
}

static int SteamUser_GetGameBadgeLevel(void* self, int nSeries, int bFoil) { return 1; }

static int SteamUser_GetPlayerSteamLevel(void* self) { return 1; }

static int SteamUser_BIsPhoneVerified(void* self) { return 1; }

static int SteamUser_BSetDurationControlOnlineState(void* self, int eNewState) { return 1; }

// ISteamUtils010

static uint32_t SteamUtils_GetSecondsSinceAppActive(void* self) { return 1; }

static uint32_t SteamUtils_GetSecondsSinceComputerActive(void* self) { return 1; }

static int SteamUtils_GetConnectedUniverse(void* self) { 
    LogMsg("[SteamUtils] GetConnectedUniverse called -> 1 (Public)");
    return 1; 
}

static uint32_t SteamUtils_GetServerRealTime(void* self) { 
    LogMsg("[SteamUtils] GetServerRealTime called");
    return (uint32_t)time(NULL); 
}

static const char* SteamUtils_GetIPCountry(void* self) { 
    LogMsg("[SteamUtils] GetIPCountry called -> US");
    return "US"; 
}

static int SteamUtils_GetImageSize(void* self, int iImage, uint32_t* pnWidth, uint32_t* pnHeight) { 
    if (pnWidth) *pnWidth = 64;
    if (pnHeight) *pnHeight = 64;
    return 1; 
}

static int SteamUtils_GetImageRGBA(void* self, int iImage, uint8_t* pubDest, int nDestBufferSize) { return 0; }

static int SteamUtils_GetCSERIPPort(void* self, uint32_t* unIP, uint16_t* usPort) { return 0; }

static uint8_t SteamUtils_GetCurrentBatteryPower(void* self) { return 255; }

static uint32_t SteamUtils_GetAppID(void* self) { 
    LogMsg("[SteamUtils] GetAppID called -> %u", g_app_id);
    return g_app_id; 
}

static void SteamUtils_SetOverlayNotificationPosition(void* self, int eNotificationPosition) {}

static int SteamUtils_IsAPICallCompleted(void* self, uint64_t hSteamAPICall, int* pbFailed) {
    if (pbFailed) *pbFailed = 0;
    return 1;
}

static int SteamUtils_GetAPICallFailureReason(void* self, uint64_t hSteamAPICall) { return 0; }

static int SteamUtils_GetAPICallResult(void* self, uint64_t hSteamAPICall, void* pCallback, int cubCallback, int iCallbackExpected, int* pbFailed) {
    if (pbFailed) *pbFailed = 0;
    return 1;
}

static void SteamUtils_RunFrame(void* self) {}

static uint32_t SteamUtils_GetIPCCallCount(void* self) { return 0; }

static void SteamUtils_SetWarningMessageHook(void* self, void* pFunction) {}

static int SteamUtils_IsOverlayEnabled(void* self) { return 0; }

static int SteamUtils_BOverlayNeedsPresent(void* self) { return 0; }

static uint64_t SteamUtils_CheckFileSignature(void* self, const char* szFileName) { return 0; }

static int SteamUtils_ShowGamepadTextInput(void* self, int eInputMode, int eLineInputMode, const char* pchDescription, uint32_t unCharMax, const char* pchExistingText) { return 0; }

static uint32_t SteamUtils_GetEnteredGamepadTextLength(void* self) { return 0; }

static int SteamUtils_GetEnteredGamepadTextInput(void* self, char* pchText, uint32_t cchText) { return 0; }

static const char* SteamUtils_GetSteamUILanguage(void* self) { 
    LogMsg("[SteamUtils] GetSteamUILanguage called -> english");
    return "english"; 
}

static int SteamUtils_IsSteamRunningInVR(void* self) { return 0; }

static void SteamUtils_SetOverlayNotificationInset(void* self, int nHorizontalInset, int nVerticalInset) {}

static int SteamUtils_IsSteamInBigPictureMode(void* self) { return 0; }

static void SteamUtils_StartVRDashboard(void* self) {}

static int SteamUtils_IsVRHeadsetStreamingEnabled(void* self) { return 0; }

static void SteamUtils_SetVRHeadsetStreamingEnabled(void* self, int bEnabled) {}

static int SteamUtils_IsSteamChinaLauncher(void* self) { return 0; }

static int SteamUtils_InitFilterText(void* self, uint32_t unFilterOptions) { return 1; }

static int SteamUtils_FilterText(void* self, int eContext, uint64_t sourceSteamID, const char* pchInputMessage, char* pchOutFilteredText, uint32_t nByteSizeOutFilteredText) { return 0; }

static int SteamUtils_GetIPv6ConnectivityState(void* self, int eProtocol) { return 0; }

static int SteamUtils_IsSteamRunningOnSteamDeck(void* self) { return 0; }

// ISteamApps008

static int SteamApps_BIsSubscribed(void* self) { 
    void* caller = _ReturnAddress();
    LogCallerInfo("SteamApps-BIsSubscribed", caller);
    LogMsg("[SteamApps] BIsSubscribed called -> 1");
    return 1; 
}

static int SteamApps_BIsLowViolence(void* self) { 
    LogMsg("[SteamApps] BIsLowViolence called -> 0");
    return 0; 
}

static int SteamApps_BIsCybercafe(void* self) { 
    LogMsg("[SteamApps] BIsCybercafe called -> 0");
    return 0; 
}

static int SteamApps_BIsVACBanned(void* self) { 
    LogMsg("[SteamApps] BIsVACBanned called -> 0");
    return 0; 
}

static const char* SteamApps_GetCurrentGameLanguage(void* self) { 
    LogMsg("[SteamApps] GetCurrentGameLanguage called -> english");
    return "english"; 
}

static const char* SteamApps_GetAvailableGameLanguages(void* self) { 
    LogMsg("[SteamApps] GetAvailableGameLanguages called -> english");
    return "english"; 
}

static int SteamApps_BIsSubscribedApp(void* self, uint32_t nAppID) { 
    void* caller = _ReturnAddress();
    LogCallerInfo("SteamApps-BIsSubscribedApp", caller);
    LogMsg("[SteamApps] BIsSubscribedApp(%u) called -> 1", nAppID);
    return 1; 
}

static int SteamApps_BIsDlcInstalled(void* self, uint32_t nAppID) { 
    LogMsg("[SteamApps] BIsDlcInstalled(%u) called -> 1", nAppID);
    return 1; 
}

static uint32_t SteamApps_GetEarliestPurchaseUnixTime(void* self, uint32_t nAppID) { 
    LogMsg("[SteamApps] GetEarliestPurchaseUnixTime(%u) called -> 1700000000", nAppID);
    return 1700000000; 
}

static int SteamApps_BIsSubscribedFromFreeWeekend(void* self) { 
    LogMsg("[SteamApps] BIsSubscribedFromFreeWeekend called -> 0");
    return 0; 
}

static int SteamApps_GetDLCCount(void* self) { 
    LogMsg("[SteamApps] GetDLCCount called -> 0");
    return 0; 
}

static int SteamApps_BGetDLCDataByIndex(void* self, int iDLC, uint32_t* pAppID, int* pbAvailable, char* pchName, int cchNameBufferSize) { 
    LogMsg("[SteamApps] BGetDLCDataByIndex(%d) called -> 0", iDLC);
    return 0; 
}

static int SteamApps_InstallDLC(void* self, uint32_t nAppID) { 
    LogMsg("[SteamApps] InstallDLC(%u) called -> 1", nAppID);
    return 1; 
}

static int SteamApps_UninstallDLC(void* self, uint32_t nAppID) { 
    LogMsg("[SteamApps] UninstallDLC(%u) called -> 1", nAppID);
    return 1; 
}

static void SteamApps_RequestAppProofOfPurchaseKey(void* self, uint32_t nAppID) {
    LogMsg("[SteamApps] RequestAppProofOfPurchaseKey(%u) called", nAppID);
}

static int SteamApps_GetCurrentBetaName(void* self, char* pchName, int cchNameBufferSize) { 
    LogMsg("[SteamApps] GetCurrentBetaName called");
    if (pchName && cchNameBufferSize > 0) pchName[0] = '\0';
    return 0; 
}

static int SteamApps_MarkContentCorrupt(void* self, int bMissingFilesOnly) { 
    LogMsg("[SteamApps] MarkContentCorrupt(missingFilesOnly=%d) CALLED! (Tiger Engine triggered MARMOT content failure)", bMissingFilesOnly);
    return 1; 
}

static uint32_t SteamApps_GetInstalledDepots(void* self, uint32_t appID, uint32_t* pvecDepots, uint32_t cMaxDepots) {
    LogMsg("[SteamApps] GetInstalledDepots(appID=%u, max=%u) called", appID, cMaxDepots);
    if (pvecDepots && cMaxDepots > 0) {
        pvecDepots[0] = 3065801;
        return 1;
    }

    return 0;
}

static uint32_t SteamApps_GetAppInstallDir(void* self, uint32_t appID, char* pchFolder, uint32_t cchFolderBufferSize) {
    LogMsg("[SteamApps] GetAppInstallDir(appID=%u) called", appID);
    if (pchFolder && cchFolderBufferSize > 0) {
        char exePath[MAX_PATH];
        if (GetModuleFileNameA(NULL, exePath, MAX_PATH)) {
            char* lastSlash = strrchr(exePath, '\\');
            if (lastSlash) *lastSlash = '\0';
            strncpy(pchFolder, exePath, cchFolderBufferSize - 1);
            pchFolder[cchFolderBufferSize - 1] = '\0';
        } else {
            GetCurrentDirectoryA(cchFolderBufferSize, pchFolder);
        }

        LogMsg("[SteamApps] -> install dir: %s", pchFolder);
        return (uint32_t)strlen(pchFolder);
    }

    return 0;
}

static int SteamApps_SetDlcContext(void* self, uint32_t nAppID) {
    LogMsg("[SteamApps] SetDlcContext(%u) called", nAppID);
    return 1;
}

static int SteamApps_BIsAppInstalled(void* self, uint32_t nAppID) { 
    LogMsg("[SteamApps] BIsAppInstalled(%u) called -> 1", nAppID);
    return 1; 
}

static uint64_t g_app_owner_storage = 76561198000001001ULL;
static void* SteamApps_GetAppOwner(void* self, void* pOutResult) { 
    LogMsg("[SteamApps] GetAppOwner(self=%p, pOut=%p) called -> %llu", self, pOutResult, g_steam_id);
    g_app_owner_storage = g_steam_id;
    if (pOutResult && pOutResult != &g_apps_interface) {
        *(uint64_t*)pOutResult = g_steam_id;
        return pOutResult;
    }

    if (self && self != &g_apps_interface) {
        *(uint64_t*)self = g_steam_id;
        return self;
    }

    return &g_app_owner_storage;
}

static const char* SteamApps_GetLaunchQueryParam(void* self, const char* pchKey) { 
    LogMsg("[SteamApps] GetLaunchQueryParam('%s') called -> empty", pchKey ? pchKey : "");
    return ""; 
}

static int SteamApps_GetDlcDownloadProgress(void* self, uint32_t nAppID, uint64_t* punBytesDownloaded, uint64_t* punBytesTotal) { 
    LogMsg("[SteamApps] GetDlcDownloadProgress(%u) called", nAppID);
    return 0; 
}

static uint32_t SteamApps_GetAppBuildId(void* self) { 
    LogMsg("[SteamApps] GetAppBuildId called -> 26136895");
    return 26136895; 
}

static void SteamApps_RequestAllProofOfPurchaseKeys(void* self) {
    LogMsg("[SteamApps] RequestAllProofOfPurchaseKeys called");
}

static uint64_t SteamApps_GetFileDetails(void* self, const char* pszFileName) {
    LogMsg("[SteamApps] GetFileDetails('%s') called", pszFileName ? pszFileName : "");
    return 0;
}

static int SteamApps_GetLaunchCommandLine(void* self, char* pszCommandLine, int cubCommandLine) {
    LogMsg("[SteamApps] GetLaunchCommandLine called");
    if (pszCommandLine && cubCommandLine > 0) pszCommandLine[0] = '\0';
    return 0;
}

static int SteamApps_BIsSubscribedFromFamilySharing(void* self) { 
    LogMsg("[SteamApps] BIsSubscribedFromFamilySharing called -> 0");
    return 0; 
}

static int SteamApps_BIsTimedTrial(void* self, uint32_t* punSecondsAllowed, uint32_t* punSecondsPlayed) {
    LogMsg("[SteamApps] BIsTimedTrial called -> 0");
    return 0;
}

// ISteamFriends017

static const char* SteamFriends_GetPersonaName(void* self) { 
    LogMsg("[SteamFriends] GetPersonaName called -> %s", g_player_name);
    return g_player_name; 
}

static uint64_t SteamFriends_SetPersonaName(void* self, const char* pchPersonaName) { return 0; }

static int SteamFriends_GetPersonaState(void* self) { return 1; }

static int SteamFriends_GetFriendCount(void* self, int iFriendFlags) { return 0; }

static uint64_t g_friend_storage = 0;
static void* SteamFriends_GetFriendByIndex(void* self, void* pOutResult, int iFriend, int iFriendFlags) {
    g_friend_storage = 0;
    if (pOutResult && pOutResult != &g_friends_interface) {
        *(uint64_t*)pOutResult = 0;
        return pOutResult;
    }

    return &g_friend_storage;
}

static int SteamFriends_GetFriendRelationship(void* self, uint64_t steamIDFriend) { return 0; }

static int SteamFriends_GetFriendPersonaState(void* self, uint64_t steamIDFriend) { return 0; }

static const char* SteamFriends_GetFriendPersonaName(void* self, uint64_t steamIDFriend) { return ""; }

static int SteamFriends_GetFriendGamePlayed(void* self, uint64_t steamIDFriend, void* pFriendGameInfo) { return 0; }

static const char* SteamFriends_GetFriendPersonaNameHistory(void* self, uint64_t steamIDFriend, int iPersonaName) { return ""; }

static int SteamFriends_GetFriendSteamLevel(void* self, uint64_t steamIDFriend) { return 1; }

static const char* SteamFriends_GetPlayerNickname(void* self, uint64_t steamIDFriend) { return ""; }

static int SteamFriends_GetFriendsGroupCount(void* self) { return 0; }

// ISteamUserStats012

static uint64_t SteamUserStats_RequestCurrentStats(void* self) {
    LogMsg("[SteamUserStats] RequestCurrentStats called -> handle 1");
    return 1;
}

static int SteamUserStats_GetStatInt(void* self, const char* pchName, int* pData) {
    LogMsg("[SteamUserStats] GetStatInt('%s') called", pchName ? pchName : "");
    if (pData) *pData = 0;
    return 1;
}

static int SteamUserStats_GetStatFloat(void* self, const char* pchName, float* pData) {
    if (pData) *pData = 0.0f;
    return 1;
}

static int SteamUserStats_SetStatInt(void* self, const char* pchName, int nData) { return 1; }

static int SteamUserStats_SetStatFloat(void* self, const char* pchName, float fData) { return 1; }

static int SteamUserStats_UpdateAvgRateStat(void* self, const char* pchName, float flCountThisSession, double dSessionLength) { return 1; }

static int SteamUserStats_GetAchievement(void* self, const char* pchName, int* pbAchieved) {
    if (pbAchieved) *pbAchieved = 0;
    return 1;
}

static int SteamUserStats_SetAchievement(void* self, const char* pchName) { return 1; }

static int SteamUserStats_ClearAchievement(void* self, const char* pchName) { return 1; }

static int SteamUserStats_GetAchievementAndUnlockTime(void* self, const char* pchName, int* pbAchieved, uint32_t* punUnlockTime) {
    if (pbAchieved) *pbAchieved = 0;
    if (punUnlockTime) *punUnlockTime = 0;
    return 1;
}

static int SteamUserStats_StoreStats(void* self) {
    LogMsg("[SteamUserStats] StoreStats called -> 1");
    return 1;
}

static int SteamUserStats_GetAchievementIcon(void* self, const char* pchName) { return 0; }

static const char* SteamUserStats_GetAchievementDisplayAttribute(void* self, const char* pchName, const char* pchKey) { return ""; }

static int SteamUserStats_IndicateAchievementProgress(void* self, const char* pchName, uint32_t nCurProgress, uint32_t nMaxProgress) { return 1; }

static uint32_t SteamUserStats_GetNumAchievements(void* self) { return 0; }

static const char* SteamUserStats_GetAchievementName(void* self, uint32_t iAchievement) { return ""; }

// ISteamInput006

static int SteamInput_Init(void* self, int bExplicitlyCallRunFrame) { 
    LogMsg("[SteamInput] Init(%d) called -> 1", bExplicitlyCallRunFrame);
    return 1; 
}

static int SteamInput_Shutdown(void* self) { 
    LogMsg("[SteamInput] Shutdown called -> 1");
    return 1; 
}

static int SteamInput_SetInputActionManifestFilePath(void* self, const char* pPath) { 
    LogMsg("[SteamInput] SetInputActionManifestFilePath('%s') called", pPath ? pPath : "");
    return 1; 
}

static void SteamInput_RunFrame(void* self, int bReservedValue) { }

static int SteamInput_BNewDataAvailable(void* self) { return 0; }

static int SteamInput_GetConnectedControllers(void* self, uint64_t* handlesOut) { return 0; }

static uint64_t SteamInput_GetActionSetHandle(void* self, const char* pszActionSetName) { return 0; }

static void SteamInput_ActivateActionSet(void* self, uint64_t inputHandle, uint64_t actionSetHandle) { }

static uint64_t SteamInput_GetCurrentActionSet(void* self, uint64_t inputHandle) { return 0; }

static void SteamInput_ActivateActionSetLayer(void* self, uint64_t inputHandle, uint64_t actionSetLayerHandle) { }

static void SteamInput_DeactivateActionSetLayer(void* self, uint64_t inputHandle, uint64_t actionSetLayerHandle) { }

static void SteamInput_DeactivateAllActionSetLayers(void* self, uint64_t inputHandle) { }

static int SteamInput_GetActiveActionSetLayers(void* self, uint64_t inputHandle, uint64_t* handlesOut) { return 0; }

static uint64_t SteamInput_GetDigitalActionHandle(void* self, const char* pszActionName) { return 0; }

static int SteamInput_GetDigitalActionData(void* self, uint64_t inputHandle, uint64_t digitalActionHandle, void* pActionData) { return 0; }

static int SteamInput_GetDigitalActionOrigins(void* self, uint64_t inputHandle, uint64_t actionSetHandle, uint64_t digitalActionHandle, int* originsOut) { return 0; }

static uint64_t SteamInput_GetAnalogActionHandle(void* self, const char* pszActionName) { return 0; }

static int SteamInput_GetAnalogActionData(void* self, uint64_t inputHandle, uint64_t analogActionHandle, void* pActionData) { return 0; }

static int SteamInput_GetAnalogActionOrigins(void* self, uint64_t inputHandle, uint64_t actionSetHandle, uint64_t analogActionHandle, int* originsOut) { return 0; }

template<int N>
static int64_t UserStub(void* self, ...) {
    void* caller = _ReturnAddress();
    LogMsg("[SteamUser-STUB] Slot %d called! (self=%p, caller=%p)", N, self, caller);
    return 0;
}

#define S8(b) (void*)UserStub<b+0>, (void*)UserStub<b+1>, (void*)UserStub<b+2>, (void*)UserStub<b+3>, (void*)UserStub<b+4>, (void*)UserStub<b+5>, (void*)UserStub<b+6>, (void*)UserStub<b+7>
static void* g_user_default_stubs[64] = {
    S8(0), S8(8), S8(16), S8(24), S8(32), S8(40), S8(48), S8(56)
};
static uint32_t SteamUser_GetAuthTicketForWebApi(void* self, const char* pchIdentity) {
    LogMsg("[SteamUser] GetAuthTicketForWebApi(self=%p, identity='%s') called -> ticket 1",
           self, pchIdentity ? pchIdentity : "NULL");
    return 1;
}

static int SteamUser_UserHasLicenseForApp(void* self, uint64_t steamID, uint32_t appID) {
    LogMsg("[SteamUser] UserHasLicenseForApp(self=%p, steamID=%llu, appID=%u) called -> 0 (HasLicense)",
           self, steamID, appID);
    return 0; // k_EUserHasLicenseResultHasLicense = 0
}

static void InitInterfaceTables() {
    for (int i = 0; i < 128; i++) g_generic_vtable[i] = (void*)MethodReturnZero;
    for (int i = 0; i < 64; i++) g_user_vtable[i] = g_user_default_stubs[i];
    for (int i = 0; i < 64; i++) g_utils_vtable[i] = (void*)MethodReturnZero;
    for (int i = 0; i < 64; i++) g_apps_vtable[i] = (void*)MethodReturnZero;
    for (int i = 0; i < 80; i++) g_friends_vtable[i] = (void*)MethodReturnZero;
    for (int i = 0; i < 64; i++) g_userstats_vtable[i] = (void*)MethodReturnZero;
    for (int i = 0; i < 64; i++) g_input_vtable[i] = (void*)MethodReturnZero;
    // User023 slots

    g_user_vtable[0] = (void*)SteamUser_GetHSteamUser;
    g_user_vtable[1] = (void*)SteamUser_BLoggedOn;
    g_user_vtable[2] = (void*)SteamUser_GetSteamID;
    g_user_vtable[13] = (void*)SteamUser_GetAuthSessionTicket;
    g_user_vtable[14] = (void*)SteamUser_GetAuthTicketForWebApi;
    g_user_vtable[17] = (void*)SteamUser_CancelAuthTicket;
    g_user_vtable[18] = (void*)SteamUser_UserHasLicenseForApp;
    g_user_vtable[21] = (void*)SteamUser_RequestEncryptedAppTicket;
    g_user_vtable[22] = (void*)SteamUser_GetEncryptedAppTicket;
    g_user_vtable[23] = (void*)SteamUser_GetGameBadgeLevel;
    g_user_vtable[24] = (void*)SteamUser_GetPlayerSteamLevel;
    g_user_vtable[26] = (void*)SteamUser_BIsPhoneVerified;
    g_user_vtable[32] = (void*)SteamUser_BSetDurationControlOnlineState;
    // Utils010 slots

    g_utils_vtable[0] = (void*)SteamUtils_GetSecondsSinceAppActive;
    g_utils_vtable[1] = (void*)SteamUtils_GetSecondsSinceComputerActive;
    g_utils_vtable[2] = (void*)SteamUtils_GetConnectedUniverse;
    g_utils_vtable[3] = (void*)SteamUtils_GetServerRealTime;
    g_utils_vtable[4] = (void*)SteamUtils_GetIPCountry;
    g_utils_vtable[5] = (void*)SteamUtils_GetImageSize;
    g_utils_vtable[6] = (void*)SteamUtils_GetImageRGBA;
    g_utils_vtable[7] = (void*)SteamUtils_GetCSERIPPort;
    g_utils_vtable[8] = (void*)SteamUtils_GetCurrentBatteryPower;
    g_utils_vtable[9] = (void*)SteamUtils_GetAppID;
    g_utils_vtable[10] = (void*)SteamUtils_SetOverlayNotificationPosition;
    g_utils_vtable[11] = (void*)SteamUtils_IsAPICallCompleted;
    g_utils_vtable[12] = (void*)SteamUtils_GetAPICallFailureReason;
    g_utils_vtable[13] = (void*)SteamUtils_GetAPICallResult;
    g_utils_vtable[14] = (void*)SteamUtils_RunFrame;
    g_utils_vtable[15] = (void*)SteamUtils_GetIPCCallCount;
    g_utils_vtable[16] = (void*)SteamUtils_SetWarningMessageHook;
    g_utils_vtable[17] = (void*)SteamUtils_IsOverlayEnabled;
    g_utils_vtable[18] = (void*)SteamUtils_BOverlayNeedsPresent;
    g_utils_vtable[19] = (void*)SteamUtils_CheckFileSignature;
    g_utils_vtable[20] = (void*)SteamUtils_ShowGamepadTextInput;
    g_utils_vtable[21] = (void*)SteamUtils_GetEnteredGamepadTextLength;
    g_utils_vtable[22] = (void*)SteamUtils_GetEnteredGamepadTextInput;
    g_utils_vtable[23] = (void*)SteamUtils_GetSteamUILanguage;
    g_utils_vtable[24] = (void*)SteamUtils_IsSteamRunningInVR;
    g_utils_vtable[25] = (void*)SteamUtils_SetOverlayNotificationInset;
    g_utils_vtable[26] = (void*)SteamUtils_IsSteamInBigPictureMode;
    g_utils_vtable[27] = (void*)SteamUtils_StartVRDashboard;
    g_utils_vtable[28] = (void*)SteamUtils_IsVRHeadsetStreamingEnabled;
    g_utils_vtable[29] = (void*)SteamUtils_SetVRHeadsetStreamingEnabled;
    g_utils_vtable[30] = (void*)SteamUtils_IsSteamChinaLauncher;
    g_utils_vtable[31] = (void*)SteamUtils_InitFilterText;
    g_utils_vtable[32] = (void*)SteamUtils_FilterText;
    g_utils_vtable[33] = (void*)SteamUtils_GetIPv6ConnectivityState;
    g_utils_vtable[34] = (void*)SteamUtils_IsSteamRunningOnSteamDeck;
    // Apps008 slots

    g_apps_vtable[0] = (void*)SteamApps_BIsSubscribed;
    g_apps_vtable[1] = (void*)SteamApps_BIsLowViolence;
    g_apps_vtable[2] = (void*)SteamApps_BIsCybercafe;
    g_apps_vtable[3] = (void*)SteamApps_BIsVACBanned;
    g_apps_vtable[4] = (void*)SteamApps_GetCurrentGameLanguage;
    g_apps_vtable[5] = (void*)SteamApps_GetAvailableGameLanguages;
    g_apps_vtable[6] = (void*)SteamApps_BIsSubscribedApp;
    g_apps_vtable[7] = (void*)SteamApps_BIsDlcInstalled;
    g_apps_vtable[8] = (void*)SteamApps_GetEarliestPurchaseUnixTime;
    g_apps_vtable[9] = (void*)SteamApps_BIsSubscribedFromFreeWeekend;
    g_apps_vtable[10] = (void*)SteamApps_GetDLCCount;
    g_apps_vtable[11] = (void*)SteamApps_BGetDLCDataByIndex;
    g_apps_vtable[12] = (void*)SteamApps_InstallDLC;
    g_apps_vtable[13] = (void*)SteamApps_UninstallDLC;
    g_apps_vtable[14] = (void*)SteamApps_RequestAppProofOfPurchaseKey;
    g_apps_vtable[15] = (void*)SteamApps_GetCurrentBetaName;
    g_apps_vtable[16] = (void*)SteamApps_MarkContentCorrupt;
    g_apps_vtable[17] = (void*)SteamApps_GetInstalledDepots;
    g_apps_vtable[18] = (void*)SteamApps_GetAppInstallDir;
    g_apps_vtable[19] = (void*)SteamApps_BIsAppInstalled;
    g_apps_vtable[20] = (void*)SteamApps_GetAppOwner;
    g_apps_vtable[21] = (void*)SteamApps_GetLaunchQueryParam;
    g_apps_vtable[22] = (void*)SteamApps_GetDlcDownloadProgress;
    g_apps_vtable[23] = (void*)SteamApps_GetAppBuildId;
    g_apps_vtable[24] = (void*)SteamApps_RequestAllProofOfPurchaseKeys;
    g_apps_vtable[25] = (void*)SteamApps_GetFileDetails;
    g_apps_vtable[26] = (void*)SteamApps_GetLaunchCommandLine;
    g_apps_vtable[27] = (void*)SteamApps_BIsSubscribedFromFamilySharing;
    g_apps_vtable[28] = (void*)SteamApps_BIsTimedTrial;
    g_apps_vtable[29] = (void*)SteamApps_SetDlcContext;
    // Friends017 slots

    g_friends_vtable[0] = (void*)SteamFriends_GetPersonaName;
    g_friends_vtable[1] = (void*)SteamFriends_SetPersonaName;
    g_friends_vtable[2] = (void*)SteamFriends_GetPersonaState;
    g_friends_vtable[3] = (void*)SteamFriends_GetFriendCount;
    g_friends_vtable[4] = (void*)SteamFriends_GetFriendByIndex;
    g_friends_vtable[5] = (void*)SteamFriends_GetFriendRelationship;
    g_friends_vtable[6] = (void*)SteamFriends_GetFriendPersonaState;
    g_friends_vtable[7] = (void*)SteamFriends_GetFriendPersonaName;
    g_friends_vtable[8] = (void*)SteamFriends_GetFriendGamePlayed;
    g_friends_vtable[9] = (void*)SteamFriends_GetFriendPersonaNameHistory;
    g_friends_vtable[10] = (void*)SteamFriends_GetFriendSteamLevel;
    g_friends_vtable[11] = (void*)SteamFriends_GetPlayerNickname;
    g_friends_vtable[12] = (void*)SteamFriends_GetFriendsGroupCount;
    // UserStats012 slots

    g_userstats_vtable[0] = (void*)SteamUserStats_RequestCurrentStats;
    g_userstats_vtable[1] = (void*)SteamUserStats_GetStatInt;
    g_userstats_vtable[2] = (void*)SteamUserStats_GetStatFloat;
    g_userstats_vtable[3] = (void*)SteamUserStats_SetStatInt;
    g_userstats_vtable[4] = (void*)SteamUserStats_SetStatFloat;
    g_userstats_vtable[5] = (void*)SteamUserStats_UpdateAvgRateStat;
    g_userstats_vtable[6] = (void*)SteamUserStats_GetAchievement;
    g_userstats_vtable[7] = (void*)SteamUserStats_SetAchievement;
    g_userstats_vtable[8] = (void*)SteamUserStats_ClearAchievement;
    g_userstats_vtable[9] = (void*)SteamUserStats_GetAchievementAndUnlockTime;
    g_userstats_vtable[10] = (void*)SteamUserStats_StoreStats;
    g_userstats_vtable[11] = (void*)SteamUserStats_GetAchievementIcon;
    g_userstats_vtable[12] = (void*)SteamUserStats_GetAchievementDisplayAttribute;
    g_userstats_vtable[13] = (void*)SteamUserStats_IndicateAchievementProgress;
    g_userstats_vtable[14] = (void*)SteamUserStats_GetNumAchievements;
    g_userstats_vtable[15] = (void*)SteamUserStats_GetAchievementName;
    // Input006 slots

    g_input_vtable[0] = (void*)SteamInput_Init;
    g_input_vtable[1] = (void*)SteamInput_Shutdown;
    g_input_vtable[2] = (void*)SteamInput_SetInputActionManifestFilePath;
    g_input_vtable[3] = (void*)SteamInput_RunFrame;
    g_input_vtable[4] = (void*)SteamInput_BNewDataAvailable;
    g_input_vtable[5] = (void*)SteamInput_GetConnectedControllers;
    g_input_vtable[6] = (void*)SteamInput_GetActionSetHandle;
    g_input_vtable[7] = (void*)SteamInput_ActivateActionSet;
    g_input_vtable[8] = (void*)SteamInput_GetCurrentActionSet;
    g_input_vtable[9] = (void*)SteamInput_ActivateActionSetLayer;
    g_input_vtable[10] = (void*)SteamInput_DeactivateActionSetLayer;
    g_input_vtable[11] = (void*)SteamInput_DeactivateAllActionSetLayers;
    g_input_vtable[12] = (void*)SteamInput_GetActiveActionSetLayers;
    g_input_vtable[13] = (void*)SteamInput_GetDigitalActionHandle;
    g_input_vtable[14] = (void*)SteamInput_GetDigitalActionData;
    g_input_vtable[15] = (void*)SteamInput_GetDigitalActionOrigins;
    g_input_vtable[16] = (void*)SteamInput_GetAnalogActionHandle;
    g_input_vtable[17] = (void*)SteamInput_GetAnalogActionData;
    g_input_vtable[18] = (void*)SteamInput_GetAnalogActionOrigins;
}

// ---------------------------------------------------------------------------

// Case-Insensitive Interface Resolver

// ---------------------------------------------------------------------------

static void* ResolveInterface(const char* ver) {
    if (!ver) return &g_generic_interface;
    if (CaseInsensitiveContains(ver, "userstats")) {
        LogMsg("[SteamAPI] Resolved '%s' -> ISteamUserStats", ver);
        return &g_userstats_interface;
    }

    if (CaseInsensitiveContains(ver, "user")) {
        LogMsg("[SteamAPI] Resolved '%s' -> ISteamUser", ver);
        return &g_user_interface;
    }

    if (CaseInsensitiveContains(ver, "utils")) {
        LogMsg("[SteamAPI] Resolved '%s' -> ISteamUtils", ver);
        return &g_utils_interface;
    }

    if (CaseInsensitiveContains(ver, "apps")) {
        LogMsg("[SteamAPI] Resolved '%s' -> ISteamApps", ver);
        return &g_apps_interface;
    }

    if (CaseInsensitiveContains(ver, "friends")) {
        LogMsg("[SteamAPI] Resolved '%s' -> ISteamFriends", ver);
        return &g_friends_interface;
    }

    if (CaseInsensitiveContains(ver, "input") || CaseInsensitiveContains(ver, "controller")) {
        LogMsg("[SteamAPI] Resolved '%s' -> ISteamInput", ver);
        return &g_input_interface;
    }

    LogMsg("[SteamAPI] Unhandled interface '%s' -> returning generic stub", ver);
    return &g_generic_interface;
}

// ---------------------------------------------------------------------------

// Callback Management & Dispatch Engine

// ---------------------------------------------------------------------------

struct CallbackEntry {
    void* pCallback;
    int iCallback;
    bool dispatched;
    int framesRemaining;
};
#define MAX_CALLBACKS 128
static CallbackEntry g_callbacks[MAX_CALLBACKS];
static int g_num_callbacks = 0;
extern "C" {
__declspec(dllexport) bool __cdecl SteamAPI_Init() {
    LogMsg("[SteamAPI] SteamAPI_Init called -> SUCCESS");
    return true;
}

__declspec(dllexport) void __cdecl SteamAPI_Shutdown() {
    void* caller = _ReturnAddress();
    LogMsg("[SteamAPI] SteamAPI_Shutdown called");
    LogCallerInfo("Shutdown-Caller", caller);
    void* stack[32];
    USHORT frames = RtlCaptureStackBackTrace(0, 32, stack, NULL);
    for (USHORT i = 0; i < frames; i++) {
        LogCallerInfo("Shutdown-Stack", stack[i]);
    }
}

__declspec(dllexport) bool __cdecl SteamAPI_RestartAppIfNecessary(uint32_t unOwnAppID) {
    LogMsg("[SteamAPI] SteamAPI_RestartAppIfNecessary(%u) called -> FALSE (no restart needed)", unOwnAppID);
    return false;
}

__declspec(dllexport) bool __cdecl SteamAPI_IsSteamRunning() {
    void* caller = _ReturnAddress();
    LogCallerInfo("SteamAPI-IsSteamRunning", caller);
    LogMsg("[SteamAPI] SteamAPI_IsSteamRunning called -> true");
    return true;
}

__declspec(dllexport) uint32_t __cdecl SteamAPI_GetHSteamUser() {
    return 1;
}

__declspec(dllexport) uint32_t __cdecl SteamAPI_GetHSteamPipe() {
    return 1;
}

__declspec(dllexport) const char* __cdecl SteamAPI_GetSteamInstallPath() {
    static char s_installPath[MAX_PATH] = {0};
    if (!s_installPath[0]) {
        char exePath[MAX_PATH];
        if (GetModuleFileNameA(NULL, exePath, MAX_PATH)) {
            char* lastSlash = strrchr(exePath, '\\');
            if (lastSlash) *lastSlash = '\0';
            strncpy(s_installPath, exePath, sizeof(s_installPath) - 1);
        } else {
            strcpy(s_installPath, "D:\\Marathon-live");
        }

    }

    LogMsg("[SteamAPI] SteamAPI_GetSteamInstallPath called -> %s", s_installPath);
    return s_installPath;
}

__declspec(dllexport) void __cdecl SteamAPI_RegisterCallback(void* pCallback, int iCallback) {
    LogMsg("[SteamAPI] RegisterCallback: id=%d (ptr=%p)", iCallback, pCallback);
    if (!pCallback) return;
    for (int i = 0; i < g_num_callbacks; i++) {
        if (g_callbacks[i].pCallback == pCallback && g_callbacks[i].iCallback == iCallback) {
            return;
        }

    }

    if (g_num_callbacks < MAX_CALLBACKS) {
        g_callbacks[g_num_callbacks].pCallback = pCallback;
        g_callbacks[g_num_callbacks].iCallback = iCallback;
        g_callbacks[g_num_callbacks].dispatched = false;
        g_callbacks[g_num_callbacks].framesRemaining = 1;
        g_num_callbacks++;
    }

}

__declspec(dllexport) void __cdecl SteamAPI_UnregisterCallback(void* pCallback) {
    for (int i = 0; i < g_num_callbacks; i++) {
        if (g_callbacks[i].pCallback == pCallback) {
            g_callbacks[i].pCallback = NULL;
            break;
        }

    }

}

#define MAX_CALL_RESULTS 32
struct CallResultEntry {
    void* pCallback;
    uint64_t hAPICall;
    int iCallback;
    int framesRemaining;
    bool dispatched;
};
static CallResultEntry g_call_results[MAX_CALL_RESULTS];
static int g_num_call_results = 0;
__declspec(dllexport) void __cdecl SteamAPI_RegisterCallResult(void* pCallback, uint64_t hAPICall) {
    LogMsg("[SteamAPI] RegisterCallResult: call=%llu, ptr=%p", hAPICall, pCallback);
    if (!pCallback) return;
    for (int i = 0; i < g_num_call_results; i++) {
        if (g_call_results[i].pCallback == pCallback && g_call_results[i].hAPICall == hAPICall) {
            return;
        }

    }

    if (g_num_call_results < MAX_CALL_RESULTS) {
        g_call_results[g_num_call_results].pCallback = pCallback;
        g_call_results[g_num_call_results].hAPICall = hAPICall;
        g_call_results[g_num_call_results].iCallback = 154; // EncryptedAppTicketResponse_t
        g_call_results[g_num_call_results].framesRemaining = 1;
        g_call_results[g_num_call_results].dispatched = false;
        g_num_call_results++;
    }

}

__declspec(dllexport) void __cdecl SteamAPI_UnregisterCallResult(void* pCallback, uint64_t hAPICall) {
    LogMsg("[SteamAPI] UnregisterCallResult: call=%llu, ptr=%p", hAPICall, pCallback);
    for (int i = 0; i < g_num_call_results; i++) {
        if (g_call_results[i].pCallback == pCallback && g_call_results[i].hAPICall == hAPICall) {
            g_call_results[i].pCallback = NULL;
            break;
        }

    }

}

static void CheckDynamicModules();
__declspec(dllexport) void __cdecl SteamAPI_RunCallbacks() {
    static int s_runcb_tick = 0;
    if ((++s_runcb_tick % 10) == 1) {
        CheckDynamicModules();
    }

    // Dispatch CallResults

    for (int i = 0; i < g_num_call_results; i++) {
        if (!g_call_results[i].pCallback || g_call_results[i].dispatched) continue;
        if (g_call_results[i].framesRemaining > 0) {
            g_call_results[i].framesRemaining--;
            continue;
        }

        void* pCb = g_call_results[i].pCallback;
        uint64_t callId = g_call_results[i].hAPICall;
        void** vtable = *(void***)pCb;
        if (!vtable) continue;
        typedef void (*CallResultRunFn)(void* self, void* pvParam, int bIOFailure, uint64_t hSteamAPICall);
        CallResultRunFn runFn = (CallResultRunFn)vtable[1];
        LogMsg("[SteamAPI] Dispatching CallResult %llu (EncryptedAppTicketResponse_t: k_EResultOK) to %p", callId, pCb);
        struct {
            int m_eResult;
        } resp = { 1 }; // 1 = k_EResultOK
        runFn(pCb, &resp, 0, callId);
        g_call_results[i].dispatched = true;
    }

    for (int i = 0; i < g_num_callbacks; i++) {
        if (!g_callbacks[i].pCallback || g_callbacks[i].dispatched) continue;
        if (g_callbacks[i].framesRemaining > 0) {
            g_callbacks[i].framesRemaining--;
            continue;
        }

        int id = g_callbacks[i].iCallback;
        void* pCb = g_callbacks[i].pCallback;
        void** vtable = *(void***)pCb;
        if (!vtable) continue;
        typedef void (*CallbackRunFn)(void* self, void* pvParam, int bIOFailure, uint64_t hSteamAPICall);
        CallbackRunFn runFn = (CallbackRunFn)vtable[0];
        if (id == 101) { // SteamServersConnected_t
            LogMsg("[SteamAPI] Dispatching callback 101 (SteamServersConnected_t) to %p", pCb);
            char dummy[16] = { 0 };
            runFn(pCb, dummy, 0, 0);
            g_callbacks[i].dispatched = true;
        } else if (id == 1101) { // UserStatsReceived_t
            LogMsg("[SteamAPI] Dispatching callback 1101 (UserStatsReceived_t) to %p", pCb);
            struct {
                uint64_t gameID;
                uint32_t result;
                uint64_t steamID;
            } stats = { (uint64_t)g_app_id, 1, g_steam_id };
            runFn(pCb, &stats, 0, 0);
            g_callbacks[i].dispatched = true;
        } else if (id == 337) { // PersonaStateChange_t
            LogMsg("[SteamAPI] Dispatching callback 337 (PersonaStateChange_t) to %p", pCb);
            struct {
                uint64_t steamID;
                int changeFlags;
            } persona = { g_steam_id, 0x0001 };
            runFn(pCb, &persona, 0, 0);
            g_callbacks[i].dispatched = true;
        } else if (id == 304) { // AvatarImageLoaded_t
            LogMsg("[SteamAPI] Dispatching callback 304 (AvatarImageLoaded_t) to %p", pCb);
            struct {
                uint64_t steamID;
                int image;
                int wide;
                int tall;
            } avatar = { g_steam_id, 1, 64, 64 };
            runFn(pCb, &avatar, 0, 0);
            g_callbacks[i].dispatched = true;
        }

    }

}

__declspec(dllexport) void* __cdecl SteamClient() {
    LogMsg("[SteamAPI] SteamClient called");
    return &g_generic_interface;
}

__declspec(dllexport) void* __cdecl SteamAPI_SteamUser_v023() {
    LogMsg("[SteamAPI] SteamAPI_SteamUser_v023 called");
    return &g_user_interface;
}

__declspec(dllexport) void* __cdecl SteamAPI_SteamUtils_v010() {
    LogMsg("[SteamAPI] SteamAPI_SteamUtils_v010 called");
    return &g_utils_interface;
}

__declspec(dllexport) void* __cdecl SteamAPI_SteamApps_v008() {
    LogMsg("[SteamAPI] SteamAPI_SteamApps_v008 called");
    return &g_apps_interface;
}

__declspec(dllexport) void* __cdecl SteamAPI_SteamFriends_v017() {
    LogMsg("[SteamAPI] SteamAPI_SteamFriends_v017 called");
    return &g_friends_interface;
}

__declspec(dllexport) void* __cdecl SteamAPI_SteamUserStats_v012() {
    LogMsg("[SteamAPI] SteamAPI_SteamUserStats_v012 called");
    return &g_userstats_interface;
}

__declspec(dllexport) void* __cdecl SteamAPI_SteamInput_v006() {
    LogMsg("[SteamAPI] SteamAPI_SteamInput_v006 called");
    return &g_input_interface;
}

__declspec(dllexport) void* __cdecl SteamInternal_CreateInterface(const char* ver) {
    LogMsg("[SteamAPI] SteamInternal_CreateInterface: %s", ver ? ver : "null");
    return ResolveInterface(ver);
}

__declspec(dllexport) void* __cdecl SteamInternal_FindOrCreateUserInterface(uint32_t hUser, const char* ver) {
    LogMsg("[SteamAPI] FindOrCreateUserInterface: user=%u, ver=%s", hUser, ver ? ver : "null");
    return ResolveInterface(ver);
}

__declspec(dllexport) void* __cdecl SteamInternal_FindOrCreateGameServerInterface(uint32_t hUser, const char* ver) {
    LogMsg("[SteamAPI] FindOrCreateGameServerInterface: user=%u, ver=%s", hUser, ver ? ver : "null");
    return ResolveInterface(ver);
}

struct ContextInitData {
    void (*pFn)(void* pCtx);
    uint64_t counter;
    char ctx[1];
};
static void CheckDynamicModules();
__declspec(dllexport) void* __cdecl SteamInternal_ContextInit(void* pContextInitData) {
    static int s_check_tick = 0;
    if ((++s_check_tick % 50) == 1) {
        CheckDynamicModules();
    }

    LogMsg("[SteamAPI] SteamInternal_ContextInit called with %p", pContextInitData);
    if (!pContextInitData) return NULL;
    ContextInitData* pData = (ContextInitData*)pContextInitData;
    void* pCtx = (void*)&pData->ctx[0];
    if (pData->pFn) {
        LogMsg("[SteamAPI] Invoking context init callback %p with ctx %p", pData->pFn, pCtx);
        pData->pFn(pCtx);
    }

    pData->counter = 1;
    return pCtx;
}


static volatile LONG g_scan_started = 0;
static volatile LONG g_bootflow_hooks_installed = 0;
static DWORD WINAPI ScanMemoryForSignonErrorThread(LPVOID lpParam);

// ---------------------------------------------------------------------------
// Non-Invasive Hardware Breakpoint (VEH) Bootflow Diagnostics
// ---------------------------------------------------------------------------
static void* g_dr0_addr = NULL; // 0x30291240 (State 8 Task Check entry)
static void* g_dr1_addr = NULL; // 0x30291251 (cmp eax, edx inside State 8 Check)
static void* g_dr2_addr = NULL; // 0x2EF4C7E0 (State 8 Entry)
static void* g_dr3_addr = NULL; // 0x2EF2A2E0 (State 9 Entry)

static LONG WINAPI BootflowVehHandler(PEXCEPTION_POINTERS pExc) {
    if (pExc->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) {
        void* rip = (void*)pExc->ContextRecord->Rip;

        if (rip == g_dr0_addr) {
            int edx_req = (int)pExc->ContextRecord->Rdx;
            void* rcx = (void*)pExc->ContextRecord->Rcx;
            uint64_t r8 = pExc->ContextRecord->R8;
            uint64_t r9 = pExc->ContextRecord->R9;
            void* caller = *(void**)pExc->ContextRecord->Rsp;

            static int s8_check_count = 0;
            static int s8_last_edx = -9999;
            s8_check_count++;

            if (s8_check_count <= 25 || edx_req != s8_last_edx || (s8_check_count % 300 == 0)) {
                LogMsg("[VEH-Check8] #%d: rcx=%p, edx(req)=%d, r8=%llu, r9=%llu (caller=%p)",
                       s8_check_count, rcx, edx_req, r8, r9, caller);
                if (s8_check_count == 1 || edx_req != s8_last_edx) {
                    void* stack[8];
                    USHORT frames = RtlCaptureStackBackTrace(0, 8, stack, NULL);
                    for (USHORT f = 0; f < frames; f++) {
                        LogCallerInfo("VEH-Check8-Stack", stack[f]);
                    }
                    if (rcx) {
                        __try {
                            uint8_t* p = (uint8_t*)rcx;
                            char hexDump[128] = {0};
                            for (int b = 0; b < 32; b++) sprintf(hexDump + b*2, "%02x", p[b]);
                            LogMsg("[VEH-Check8] Context rcx preview (32B): %s", hexDump);
                        } __except (EXCEPTION_EXECUTE_HANDLER) {}
                    }
                }
                s8_last_edx = edx_req;
            }
            pExc->ContextRecord->EFlags |= 0x10000;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        else if (rip == g_dr1_addr) {
            int eax_done = (int)pExc->ContextRecord->Rax;
            int edx_req = (int)pExc->ContextRecord->Rdx;

            static int s8_eval_count = 0;
            static int s8_last_done = -9999;
            s8_eval_count++;

            if (s8_eval_count <= 25 || eax_done != s8_last_done || (s8_eval_count % 300 == 0)) {
                LogMsg("[VEH-Check8-EVAL] #%d: eax(completed)=%d vs edx(required)=%d -> Branch: %s",
                       s8_eval_count, eax_done, edx_req,
                       (eax_done >= edx_req) ? "TRANSITION (eax >= edx)" : "WAIT (eax < edx)");
                s8_last_done = eax_done;
            }
            pExc->ContextRecord->EFlags |= 0x10000;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        else if (rip == g_dr2_addr) {
            void* caller = *(void**)pExc->ContextRecord->Rsp;
            LogMsg("[VEH-Stage8-ENTRY] Stage 8 (bootflow sos actions) ENTERED! rcx=%p, caller=%p",
                   (void*)pExc->ContextRecord->Rcx, caller);
            void* stack[8];
            USHORT frames = RtlCaptureStackBackTrace(0, 8, stack, NULL);
            for (USHORT f = 0; f < frames; f++) {
                LogCallerInfo("VEH-Stage8-Stack", stack[f]);
            }
            pExc->ContextRecord->EFlags |= 0x10000;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        else if (rip == g_dr3_addr) {
            void* caller = *(void**)pExc->ContextRecord->Rsp;
            LogMsg("[VEH-Stage9-ENTRY] Stage 9 (bootflow checking content manifest) ENTERED! rcx=%p, caller=%p",
                   (void*)pExc->ContextRecord->Rcx, caller);
            pExc->ContextRecord->EFlags |= 0x10000;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void ApplyDebugRegistersToThread(HANDLE hThread) {
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(hThread, &ctx)) {
        ctx.Dr0 = (DWORD64)g_dr0_addr;
        ctx.Dr1 = (DWORD64)g_dr1_addr;
        ctx.Dr2 = (DWORD64)g_dr2_addr;
        ctx.Dr3 = (DWORD64)g_dr3_addr;
        ctx.Dr6 = 0;
        ctx.Dr7 = 0x55; // 0b01010101: local enable for Dr0, Dr1, Dr2, Dr3 (condition: execute)
        SetThreadContext(hThread, &ctx);
    }
}

static DWORD WINAPI DebugRegisterMonitorThread(LPVOID lpParam) {
    LogMsg("[VEH-Monitor] Debug register monitor thread active");
    DWORD curPid = GetCurrentProcessId();
    DWORD curTid = GetCurrentThreadId();

    for (int loop = 0; loop < 180; loop++) {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te;
            te.dwSize = sizeof(te);
            if (Thread32First(hSnap, &te)) {
                do {
                    if (te.th32OwnerProcessID == curPid && te.th32ThreadID != curTid) {
                        HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                        if (hThread) {
                            SuspendThread(hThread);
                            ApplyDebugRegistersToThread(hThread);
                            ResumeThread(hThread);
                            CloseHandle(hThread);
                        }
                    }
                } while (Thread32Next(hSnap, &te));
            }
            CloseHandle(hSnap);
        }
        Sleep(500);
    }
    return 0;
}

static void InstallBootflowHooks() {
    LogMsg("[Bootflow-Hooks] Clean baseline mode active (no debug registers)");
}

__declspec(dllexport) int __cdecl SteamInternal_SteamAPI_Init(const char* pszExplicitOptIn, void* pError) {
    LogMsg("[SteamAPI] SteamInternal_SteamAPI_Init called -> SUCCESS (k_ESteamAPIInitResult_OK = 0)");
    if (pError) {
        *(char*)pError = '\0';
    }

    if (InterlockedCompareExchange(&g_scan_started, 1, 0) == 0) {
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ScanMemoryForSignonErrorThread, NULL, 0, NULL);
    }

    if (InterlockedCompareExchange(&g_bootflow_hooks_installed, 1, 0) == 0) {
        InstallBootflowHooks();
    }

    return 0; // 0 == k_ESteamAPIInitResult_OK
}

} // extern "C"
// ---------------------------------------------------------------------------

// Network & Crypto Egress Hooking (WS2_32.dll, CRYPT32.dll)

// ---------------------------------------------------------------------------

typedef BOOL (WINAPI *CertVerifyCertificateChainPolicy_t)(
    LPCSTR pszPolicyOID,
    PCCERT_CHAIN_CONTEXT pChainContext,
    PCERT_CHAIN_POLICY_PARA pPolicyPara,
    PCERT_CHAIN_POLICY_STATUS pPolicyStatus
);
static CertVerifyCertificateChainPolicy_t g_real_CertVerifyCertificateChainPolicy = NULL;

static DWORD WINAPI RuntimeSdrMonitorThread(LPVOID lpParam) {
    LogMsg("[SDR-Monitor] Thread started");
    SetDllDirectoryA("C:\\Program Files (x86)\\Steam");
    HMODULE hSteamclient = GetModuleHandleA("steamclient64.dll");
    if (!hSteamclient) {
        hSteamclient = LoadLibraryA("C:\\Program Files (x86)\\Steam\\steamclient64.dll");
        if (hSteamclient) {
            LogMsg("[SDR-Monitor] Loaded steamclient64.dll from Steam directory");
        } else {
            LogMsg("[SDR-Monitor] Failed to load steamclient64.dll (err=%lu)", GetLastError());
        }
    }
    while (1) {
        Sleep(3000);
        if (!hSteamclient) {
            hSteamclient = GetModuleHandleA("steamclient64.dll");
            if (!hSteamclient) hSteamclient = LoadLibraryA("C:\\Program Files (x86)\\Steam\\steamclient64.dll");
        }
        if (hSteamclient) {
            typedef void* (*CreateInterfaceFn)(const char* pName, int* pReturnCode);
            CreateInterfaceFn pfnCreate = (CreateInterfaceFn)GetProcAddress(hSteamclient, "CreateInterface");
            if (pfnCreate) {
                int returnCode = 0;
                void* pUtils = NULL;
                __try {
                    pUtils = pfnCreate("SteamNetworkingUtils004", &returnCode);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    pUtils = NULL;
                }
                if (pUtils) {
                    void** vtbl = *(void***)pUtils;
                    if (vtbl && vtbl[1]) {
                        typedef int (__fastcall *GetRelayNetworkStatusFn)(void*, void*);
                        GetRelayNetworkStatusFn pfnStatus = (GetRelayNetworkStatusFn)vtbl[1];
                        struct {
                            int m_eAvail;
                            int m_bPingMeasurementInProgress;
                            int m_eAvailNetworkConfig;
                            int m_eAvailAnyRelay;
                            char m_szDebugMsg[256];
                        } status;
                        memset(&status, 0, sizeof(status));
                        int avail = 0;
                        __try {
                            avail = pfnStatus(pUtils, &status);
                        } __except (EXCEPTION_EXECUTE_HANDLER) {
                            avail = -999;
                        }
                        const char* availStr = "Unknown";
                        if (avail == 100) availStr = "Current(100)";
                        else if (avail == 3) availStr = "Attempting(3)";
                        else if (avail == 2) availStr = "Waiting(2)";
                        else if (avail == 1) availStr = "NeverTried(1)";
                        else if (avail == -10) availStr = "Retrying(-10)";
                        else if (avail == -100) availStr = "Previously(-100)";
                        else if (avail == -101) availStr = "Failed(-101)";
                        else if (avail == -102) availStr = "CannotTry(-102)";

                        const char* cfgStr = (status.m_eAvailNetworkConfig == 100) ? "Current(100)" :
                                             (status.m_eAvailNetworkConfig == 3) ? "Attempting(3)" :
                                             (status.m_eAvailNetworkConfig == 2) ? "Waiting(2)" :
                                             (status.m_eAvailNetworkConfig == 1) ? "NeverTried(1)" : "Other";
                        const char* relayStr = (status.m_eAvailAnyRelay == 100) ? "Current(100)" :
                                               (status.m_eAvailAnyRelay == 3) ? "Attempting(3)" :
                                               (status.m_eAvailAnyRelay == 2) ? "Waiting(2)" :
                                               (status.m_eAvailAnyRelay == 1) ? "NeverTried(1)" : "Other";

                        LogMsg("[SDR-Runtime] Avail=%s, PingInProg=%d, NetConfig=%s(%d), AnyRelay=%s(%d), Msg='%s'",
                               availStr, status.m_bPingMeasurementInProgress,
                               cfgStr, status.m_eAvailNetworkConfig,
                               relayStr, status.m_eAvailAnyRelay,
                               status.m_szDebugMsg);
                    }
                }
            }
        }
    }
    return 0;
}

static DWORD WINAPI ScanMemoryForSignonErrorThread(LPVOID lpParam) {
    LogMsg("[MemScan] ScanMemory thread disabled to preserve execution stability");
    return 0;
}
static DWORD WINAPI Unused_ScanMemoryForSignonErrorThread(LPVOID lpParam) {
    Sleep(500);
    HMODULE hExe = GetModuleHandle(NULL);
    if (!hExe) return 0;
    
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hExe;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hExe + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    
    DWORD imageSize = nt->OptionalHeader.SizeOfImage;
    BYTE* base = (BYTE*)hExe;
    LogMsg("[MemScan] Starting Marathon.exe memory scan (base=%p, size=0x%X)...", base, imageSize);
    
    // Start SDR Monitor thread
    static volatile LONG g_sdr_mon_started = 0;
    if (InterlockedCompareExchange(&g_sdr_mon_started, 1, 0) == 0) {
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)RuntimeSdrMonitorThread, NULL, 0, NULL);
    }

    // 1. Dump 16KB around Bootflow Table at Marathon.exe+0x32DA2690
    __try {
        BYTE* bfTable = base + 0x32DA2690;
        FILE* fpBf = fopen("D:/Marathon-live/mem_bootflow_table.bin", "wb");
        if (fpBf) {
            fwrite(bfTable - 0x1000, 1, 0x4000, fpBf);
            fclose(fpBf);
            LogMsg("[MemScan] Dumped 16KB around Bootflow Table (0x32DA2690) to mem_bootflow_table.bin");
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        LogMsg("[MemScan] Exception dumping bootflow table");
    }

    __try {
        BYTE* vt78 = base + 0x2EF1EDC0;
        FILE* fpVt = fopen("D:/Marathon-live/mem_vtable_2EF1EDC0.bin", "wb");
        if (fpVt) {
            fwrite(vt78 - 0x100, 1, 0x1000, fpVt);
            fclose(fpVt);
            LogMsg("[MemScan] Dumped 4KB around Stage 7/8 vtable (0x2EF1EDC0)");
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    __try {
        BYTE* vt9 = base + 0x302832A0;
        FILE* fpVt = fopen("D:/Marathon-live/mem_vtable_302832A0.bin", "wb");
        if (fpVt) {
            fwrite(vt9 - 0x100, 1, 0x1000, fpVt);
            fclose(fpVt);
            LogMsg("[MemScan] Dumped 4KB around Stage 9 vtable (0x302832A0)");
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    // Dump 64KB chunks around key bootflow stage code areas
    __try {
        BYTE* p = base + 0x2EF40000;
        FILE* fp = fopen("D:/Marathon-live/mem_area_2EF40000.bin", "wb");
        if (fp) {
            fwrite(p, 1, 0x10000, fp);
            fclose(fp);
            LogMsg("[MemScan] Dumped 64KB of 0x2EF40000");
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    __try {
        BYTE* p = base + 0x2EF70000;
        FILE* fp = fopen("D:/Marathon-live/mem_area_2EF70000.bin", "wb");
        if (fp) {
            fwrite(p, 1, 0x10000, fp);
            fclose(fp);
            LogMsg("[MemScan] Dumped 64KB of 0x2EF70000");
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    __try {
        BYTE* p = base + 0x30050000;
        FILE* fp = fopen("D:/Marathon-live/mem_area_30050000.bin", "wb");
        if (fp) {
            fwrite(p, 1, 0x10000, fp);
            fclose(fp);
            LogMsg("[MemScan] Dumped 64KB of 0x30050000");
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    __try {
        BYTE* p = base + 0x30280000;
        FILE* fp = fopen("D:/Marathon-live/mem_area_30280000.bin", "wb");
        if (fp) {
            fwrite(p, 1, 0x20000, fp); // 128KB covering 0x30280000 - 0x302A0000
            fclose(fp);
            LogMsg("[MemScan] Dumped 128KB of 0x30280000");
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    // Dump State 7 entry function (0x2EF77E60) - 8KB
    __try {
        BYTE* fn7 = base + 0x2EF77E60;
        FILE* fp = fopen("D:/Marathon-live/mem_func_state7_2EF77E60.bin", "wb");
        if (fp) {
            fwrite(fn7, 1, 0x2000, fp);
            fclose(fp);
            LogMsg("[MemScan] Dumped 8KB of State 7 entry function (0x2EF77E60)");
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    // Dump State 6 entry function (0x3005D820) - 8KB
    __try {
        BYTE* fn6 = base + 0x3005D820;
        FILE* fp = fopen("D:/Marathon-live/mem_func_state6_3005D820.bin", "wb");
        if (fp) {
            fwrite(fn6, 1, 0x2000, fp);
            fclose(fp);
            LogMsg("[MemScan] Dumped 8KB of State 6 entry function (0x3005D820)");
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    // Dump State 9 stub/destructor (0x2EF2A2E0) - 8KB
    __try {
        BYTE* fn9 = base + 0x2EF2A2E0;
        FILE* fp = fopen("D:/Marathon-live/mem_func_state9_2EF2A2E0.bin", "wb");
        if (fp) {
            fwrite(fn9, 1, 0x2000, fp);
            fclose(fp);
            LogMsg("[MemScan] Dumped 8KB of State 9 function (0x2EF2A2E0)");
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    // Dump direct_settings string reference regions
    __try {
        BYTE* ds1 = base + 0x32D28F30;
        FILE* fp = fopen("D:/Marathon-live/mem_direct_settings_32D28F30.bin", "wb");
        if (fp) {
            fwrite(ds1 - 0x200, 1, 0x1000, fp);
            fclose(fp);
            LogMsg("[MemScan] Dumped 4KB around direct_settings (0x32D28F30)");
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    __try {
        BYTE* ds2 = base + 0x32DA9B86;
        FILE* fp = fopen("D:/Marathon-live/mem_direct_settings_32DA9B86.bin", "wb");
        if (fp) {
            fwrite(ds2 - 0x200, 1, 0x1000, fp);
            fclose(fp);
            LogMsg("[MemScan] Dumped 4KB around direct_settings (0x32DA9B86)");
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    __try {
        BYTE* ds3 = base + 0x32DC701C;
        FILE* fp = fopen("D:/Marathon-live/mem_direct_settings_32DC701C.bin", "wb");
        if (fp) {
            fwrite(ds3 - 0x200, 1, 0x1000, fp);
            fclose(fp);
            LogMsg("[MemScan] Dumped 4KB around direct_settings (0x32DC701C)");
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    // 2. Scan committed data/rodata for key strings:
    const char* search_strings[] = {
        "bootflow sos actions",
        "bootflow checking content manifest",
        "direct_settings",
        "global.json",
        "/cfg_a/",
        "lmdetail.json",
        "state_duration",
        "world_controller.bootflow"
    };
    int num_search_strings = sizeof(search_strings) / sizeof(search_strings[0]);
    DWORD found_str_rvas[32] = {0};
    int found_str_count = 0;

    MEMORY_BASIC_INFORMATION mbi;
    BYTE* cur = base;
    BYTE* end = base + imageSize;

    while (cur < end && VirtualQuery(cur, &mbi, sizeof(mbi))) {
        if ((mbi.State == MEM_COMMIT) && !(mbi.Protect & PAGE_GUARD) &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
            BYTE* pstart = (BYTE*)mbi.BaseAddress;
            SIZE_T plen = mbi.RegionSize;
            if (pstart + plen > end) plen = end - pstart;

            for (int s = 0; s < num_search_strings; s++) {
                const char* needle = search_strings[s];
                size_t nlen = strlen(needle);
                if (plen < nlen) continue;
                for (SIZE_T i = 0; i <= plen - nlen; i++) {
                    if (memcmp(pstart + i, needle, nlen) == 0) {
                        DWORD str_rva = (DWORD)((pstart + i) - base);
                        LogMsg("[StrScan] Found '%s' at Marathon.exe+0x%X (VA=%p)", needle, str_rva, pstart + i);
                        if (found_str_count < 30) {
                            found_str_rvas[found_str_count++] = str_rva;
                        }
                    }
                }
            }
        }
        cur = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
    }

    // 3. Comprehensive Scan for RIP-relative & immediate references to bootflow table, strings, and found strings
    DWORD bf_tbl_min = 0x32DA2690;
    DWORD bf_tbl_max = 0x32DA2800;
    DWORD bf_str_min = 0x32DA2A00;
    DWORD bf_str_max = 0x32DA2D00;
    DWORD err_tbl_min = 0x3683D9E0;
    DWORD err_tbl_max = 0x3683DC00;
    int ref_count = 0;

    cur = base;
    while (cur < end && VirtualQuery(cur, &mbi, sizeof(mbi))) {
        if ((mbi.State == MEM_COMMIT) && !(mbi.Protect & PAGE_GUARD) && 
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
            
            BYTE* page_start = (BYTE*)mbi.BaseAddress;
            SIZE_T page_len = mbi.RegionSize;
            if (page_start + page_len > end) page_len = end - page_start;

            if (page_len >= 12) {
                for (SIZE_T i = 0; i <= page_len - 12; i++) {
                    BYTE b0 = page_start[i];
                    BYTE b1 = page_start[i+1];
                    DWORD instr_rva = (DWORD)((page_start + i) - base);
                    
                    if (instr_rva >= 0xC972000 && instr_rva <= 0xC974000) continue;

                    DWORD target = 0;
                    DWORD rip_after = 0;
                    int32_t disp = 0;

                    if (b0 == 0x48 || b0 == 0x4C || b0 == 0x44) {
                        BYTE modrm = page_start[i+2];
                        if ((modrm & 0xC7) == 0x05) {
                            if (b1 == 0x8D || b1 == 0x8B || b1 == 0x89) {
                                disp = *(int32_t*)(page_start + i + 3);
                                rip_after = instr_rva + 7;
                                target = rip_after + disp;
                            } else if (b1 == 0xC7) {
                                disp = *(int32_t*)(page_start + i + 3);
                                rip_after = instr_rva + 11;
                                target = rip_after + disp;
                            }
                        }
                    } else if (b0 == 0x8D || b0 == 0x8B || b0 == 0x89 || b0 == 0x39 || b0 == 0x3B || b0 == 0x85) {
                        if ((b1 & 0xC7) == 0x05) {
                            disp = *(int32_t*)(page_start + i + 2);
                            rip_after = instr_rva + 6;
                            target = rip_after + disp;
                        }
                    } else if (b0 == 0xC7 && ((b1 & 0xC7) == 0x05)) {
                        disp = *(int32_t*)(page_start + i + 2);
                        rip_after = instr_rva + 10;
                        target = rip_after + disp;
                    } else if ((b0 == 0x80 || b0 == 0x83) && ((b1 & 0xC7) == 0x05)) {
                        disp = *(int32_t*)(page_start + i + 2);
                        rip_after = instr_rva + 7;
                        target = rip_after + disp;
                    }

                    bool hit = false;
                    const char* hit_desc = "unknown";
                    if (target != 0) {
                        if (target >= bf_tbl_min && target <= bf_tbl_max) {
                            hit = true;
                            hit_desc = "bootflow table";
                        } else if (target >= bf_str_min && target <= bf_str_max) {
                            hit = true;
                            hit_desc = "bootflow stage string";
                        } else if (target >= err_tbl_min && target <= err_tbl_max) {
                            hit = true;
                            hit_desc = "error table";
                        } else {
                            for (int f = 0; f < found_str_count; f++) {
                                if (target == found_str_rvas[f]) {
                                    hit = true;
                                    hit_desc = "scanned keyword string";
                                    break;
                                }
                            }
                        }
                    }

                    if (hit) {
                        LogMsg("[MemScan] Found ref to %s 0x%X at Marathon.exe+0x%X (VA=%p, disp=0x%X)",
                               hit_desc, target, instr_rva, page_start + i, disp);
                        char fn[MAX_PATH];
                        snprintf(fn, sizeof(fn), "D:/Marathon-live/code_bootflow_ref_%X.bin", instr_rva);
                        FILE* fp = fopen(fn, "wb");
                        if (fp) {
                            BYTE* s = (page_start + i >= base + 256) ? (page_start + i - 256) : page_start;
                            fwrite(s, 1, 512, fp);
                            fclose(fp);
                            LogMsg("[MemScan] Dumped 512 bytes surrounding code to %s", fn);
                        }
                        ref_count++;
                    }
                }
            }
        }
        cur = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
    }
    LogMsg("[MemScan] Scan completed. Found %d references to bootflow/strings.", ref_count);
    return 0;
}


static BOOL WINAPI Hook_CertVerifyCertificateChainPolicy(
    LPCSTR pszPolicyOID,
    PCCERT_CHAIN_CONTEXT pChainContext,
    PCERT_CHAIN_POLICY_PARA pPolicyPara,
    PCERT_CHAIN_POLICY_STATUS pPolicyStatus
) {
    void* caller = _ReturnAddress();
    if (InterlockedCompareExchange(&g_scan_started, 1, 0) == 0) {
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ScanMemoryForSignonErrorThread, NULL, 0, NULL);
    }
    static volatile LONG g_tls_dumped = 0;
    if (InterlockedCompareExchange(&g_tls_dumped, 1, 0) == 0) {
        FILE* fpTls = fopen("D:/Marathon-live/mem_tls_caller.bin", "wb");
        if (fpTls) {
            BYTE* s = ((uintptr_t)caller >= 256) ? ((BYTE*)caller - 256) : (BYTE*)caller;
            fwrite(s, 1, 512, fpTls);
            fclose(fpTls);
            LogMsg("[Crypto] Dumped 512 bytes around TLS caller (%p) to mem_tls_caller.bin", caller);
        }
    }
    char certSubject[256] = "none";
    char certIssuer[256] = "none";
    if (pChainContext && pChainContext->cChain > 0 && pChainContext->rgpChain[0]->cElement > 0) {
        PCCERT_CONTEXT cert = pChainContext->rgpChain[0]->rgpElement[0]->pCertContext;
        if (cert) {
            CertGetNameStringA(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, certSubject, sizeof(certSubject));
            CertGetNameStringA(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, certIssuer, sizeof(certIssuer));
        }

    }

    const char* policyDesc = "UNKNOWN";
    if (pszPolicyOID == (LPCSTR)1 || (intptr_t)pszPolicyOID == 1) policyDesc = "BASE (1)";
    else if (pszPolicyOID == (LPCSTR)2 || (intptr_t)pszPolicyOID == 2) policyDesc = "AUTHENTICODE (2)";
    else if (pszPolicyOID == (LPCSTR)3 || (intptr_t)pszPolicyOID == 3) policyDesc = "NT_AUTH (3)";
    else if (pszPolicyOID == (LPCSTR)4 || (intptr_t)pszPolicyOID == 4) policyDesc = "SSL (4)";
    else if ((uintptr_t)pszPolicyOID > 0xFFFF) policyDesc = pszPolicyOID;

    LogMsg("[Crypto] CertVerifyCertificateChainPolicy called (policy=%s, subject='%s', issuer='%s')",
           policyDesc, certSubject, certIssuer);
    LogCallerInfo("Crypto-Caller", caller);

    void* stack[8];
    USHORT frames = RtlCaptureStackBackTrace(0, 8, stack, NULL);
    for (USHORT f = 0; f < frames; f++) {
        LogCallerInfo("Crypto-Stack", stack[f]);
    }

    DWORD dwErrorBefore = pPolicyStatus ? pPolicyStatus->dwError : 0xFFFFFFFF;
    BOOL realRes = FALSE;
    if (g_real_CertVerifyCertificateChainPolicy) {
        realRes = g_real_CertVerifyCertificateChainPolicy(pszPolicyOID, pChainContext, pPolicyPara, pPolicyStatus);
    }
    DWORD dwErrorAfter = pPolicyStatus ? pPolicyStatus->dwError : 0xFFFFFFFF;
    LogMsg("[Crypto] CertVerifyCertificateChainPolicy (%s) -> realRes=%d, dwErrorBefore=0x%08X, dwErrorAfter=0x%08X",
           policyDesc, realRes, dwErrorBefore, dwErrorAfter);
    if (pPolicyStatus && pPolicyStatus->dwError != 0) {
        LogMsg("[Crypto] Natural chain error detected (0x%08X), normalizing to NO_ERROR for local emulation", pPolicyStatus->dwError);
        pPolicyStatus->dwError = 0; // CERT_TRUST_NO_ERROR = 0
    }
    return TRUE;
}

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
    LogMsg("[DNS] getaddrinfo(node='%s', service='%s')", pNodeName ? pNodeName : "NULL", pServiceName ? pServiceName : "NULL");
    PCSTR node = pNodeName;
    PCSTR service = pServiceName;
    if (pNodeName && (strstr(pNodeName, "deadorbit") || strstr(pNodeName, "bungie") || strstr(pNodeName, "goliath") || strstr(pNodeName, "marathon") || strstr(pNodeName, "playfab") || strstr(pNodeName, "gravityshavings"))) {
        LogMsg("[Egress] Intercepted DNS getaddrinfo for '%s' -> Redirecting to '%s:%s'",
               pNodeName, g_server_ip, g_server_port);
        node = g_server_ip;
        if (pServiceName && (strcmp(pServiceName, "443") == 0 || strcmp(pServiceName, "https") == 0)) {
            service = g_server_port;
        }

    }

    int res = g_real_getaddrinfo ? g_real_getaddrinfo(node, service, pHints, ppResult) : WSAEFAULT;
    if (res != 0 && node == g_server_ip && g_real_getaddrinfo) {
        res = g_real_getaddrinfo(g_server_ip, service, NULL, ppResult);
    }

    return res;
}

typedef int (WSAAPI *GetAddrInfoW_t)(
    PCWSTR pNodeName,
    PCWSTR pServiceName,
    const ADDRINFOW *pHints,
    PADDRINFOW *ppResult
);
static GetAddrInfoW_t g_real_GetAddrInfoW = NULL;
static int WSAAPI Hook_GetAddrInfoW(
    PCWSTR pNodeName,
    PCWSTR pServiceName,
    const ADDRINFOW *pHints,
    PADDRINFOW *ppResult
) {
    if (pNodeName) {
        char nodeA[256] = {0};
        WideCharToMultiByte(CP_UTF8, 0, pNodeName, -1, nodeA, sizeof(nodeA), NULL, NULL);
        LogMsg("[DNS] GetAddrInfoW(node='%s')", nodeA);
        if (strstr(nodeA, "deadorbit") || strstr(nodeA, "bungie") || strstr(nodeA, "goliath") || strstr(nodeA, "marathon") || strstr(nodeA, "playfab") || strstr(nodeA, "gravityshavings")) {
            LogMsg("[Egress] Intercepted DNS GetAddrInfoW for '%s' -> Redirecting to '%s'", nodeA, g_server_ip);
            wchar_t wServerIp[64] = L"127.0.0.1";
            return g_real_GetAddrInfoW ? g_real_GetAddrInfoW(wServerIp, pServiceName, pHints, ppResult) : WSAEFAULT;
        }

    }

    return g_real_GetAddrInfoW ? g_real_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult) : WSAEFAULT;
}

typedef INT (WSAAPI *GetAddrInfoExW_t)(
    PCWSTR pName,
    PCWSTR pServiceName,
    DWORD dwNamespace,
    LPGUID lpNspId,
    const ADDRINFOEXW *pHints,
    PADDRINFOEXW *ppResult,
    struct timeval *timeout,
    LPOVERLAPPED lpOverlapped,
    LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine,
    LPHANDLE lpNameHandle
);
static GetAddrInfoExW_t g_real_GetAddrInfoExW = NULL;
static INT WSAAPI Hook_GetAddrInfoExW(
    PCWSTR pName,
    PCWSTR pServiceName,
    DWORD dwNamespace,
    LPGUID lpNspId,
    const ADDRINFOEXW *pHints,
    PADDRINFOEXW *ppResult,
    struct timeval *timeout,
    LPOVERLAPPED lpOverlapped,
    LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine,
    LPHANDLE lpNameHandle
) {
    PCWSTR node = pName;
    if (pName) {
        char nodeA[256] = {0};
        WideCharToMultiByte(CP_UTF8, 0, pName, -1, nodeA, sizeof(nodeA), NULL, NULL);
        LogMsg("[DNS] GetAddrInfoExW(node='%s')", nodeA);
        if (strstr(nodeA, "deadorbit") || strstr(nodeA, "bungie") || strstr(nodeA, "goliath") ||
            strstr(nodeA, "marathon") || strstr(nodeA, "playfab") || strstr(nodeA, "gravityshavings")) {
            LogMsg("[Egress] Intercepted DNS GetAddrInfoExW for '%s' -> Redirecting to 127.0.0.1", nodeA);
            wchar_t wServerIp[64] = L"127.0.0.1";
            return g_real_GetAddrInfoExW ?
                g_real_GetAddrInfoExW(wServerIp, pServiceName, dwNamespace, lpNspId, pHints, ppResult, timeout, lpOverlapped, lpCompletionRoutine, lpNameHandle) :
                WSAEFAULT;
        }

    }

    return g_real_GetAddrInfoExW ?
        g_real_GetAddrInfoExW(node, pServiceName, dwNamespace, lpNspId, pHints, ppResult, timeout, lpOverlapped, lpCompletionRoutine, lpNameHandle) :
        WSAEFAULT;
}

typedef struct hostent* (WSAAPI *gethostbyname_t)(const char* name);
static gethostbyname_t g_real_gethostbyname = NULL;
static struct hostent* WSAAPI Hook_gethostbyname(const char* name) {
    LogMsg("[DNS] gethostbyname('%s')", name ? name : "NULL");
    if (name && (strstr(name, "deadorbit") || strstr(name, "bungie") || strstr(name, "goliath") || strstr(name, "marathon") || strstr(name, "playfab") || strstr(name, "gravityshavings"))) {
        LogMsg("[Egress] Intercepted DNS gethostbyname for '%s' -> Redirecting to '%s'",
               name, g_server_ip);
        return g_real_gethostbyname ? g_real_gethostbyname(g_server_ip) : NULL;
    }

    return g_real_gethostbyname ? g_real_gethostbyname(name) : NULL;
}

typedef struct _UNICODE_STRING_PEB {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING_PEB;
typedef struct _LDR_DATA_TABLE_ENTRY_PEB {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING_PEB FullDllName;
    UNICODE_STRING_PEB BaseDllName;
} LDR_DATA_TABLE_ENTRY_PEB;
typedef struct _PEB_LDR_DATA_PEB {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
} PEB_LDR_DATA_PEB;
static HMODULE g_hooked_modules[256];
static int g_num_hooked_modules = 0;
static bool IsModuleHooked(HMODULE hMod) {
    for (int i = 0; i < g_num_hooked_modules; i++) {
        if (g_hooked_modules[i] == hMod) return true;
    }
    return false;
}

static void MarkModuleHooked(HMODULE hMod) {
    if (g_num_hooked_modules < 256 && !IsModuleHooked(hMod)) {
        g_hooked_modules[g_num_hooked_modules++] = hMod;
    }
}

#ifndef SIO_GET_EXTENSION_FUNCTION_POINTER
#define SIO_GET_EXTENSION_FUNCTION_POINTER 0xC8000006
#endif
static const GUID g_WSAID_CONNECTEX = {0x25a207b9,0xddf3,0x4660,{0x8e,0xe9,0x76,0xe5,0x8c,0x74,0x06,0x3e}};
typedef BOOL (PASCAL *ConnectEx_t)(
    SOCKET s, const struct sockaddr *name, int namelen,
    PVOID lpSendBuffer, DWORD dwSendDataLength, LPDWORD lpdwBytesSent,
    LPOVERLAPPED lpOverlapped
);
static ConnectEx_t g_real_ConnectEx = NULL;
static BOOL PASCAL Hook_ConnectEx(
    SOCKET s, const struct sockaddr *name, int namelen,
    PVOID lpSendBuffer, DWORD dwSendDataLength, LPDWORD lpdwBytesSent,
    LPOVERLAPPED lpOverlapped
) {
    void* caller = _ReturnAddress();
    LogCallerInfo("ConnectEx", caller);
    if (name && name->sa_family == AF_INET) {
        struct sockaddr_in sin_copy;
        memcpy(&sin_copy, name, sizeof(sin_copy));
        uint16_t port = ntohs(sin_copy.sin_port);
        char ip[32] = {0};
        inet_ntop(AF_INET, &sin_copy.sin_addr, ip, sizeof(ip));
        LogMsg("[TCP] ConnectEx(IPv4) to %s:%d (socket=%lld)", ip, port, (long long)s);
        if (port == 443 || port == 80 || (strcmp(ip, "127.0.0.1") != 0 && (port == 8080 || port == 7777))) {
            uint16_t target_port = (port == 80) ? 80 : ((port == 443) ? 443 : ((port == 7777) ? 7777 : (uint16_t)atoi(g_server_port)));
            LogMsg("[Egress] Redirecting IPv4 ConnectEx() from %s:%d to %s:%u",
                   ip, port, g_server_ip, target_port);
            sin_copy.sin_addr.s_addr = inet_addr(g_server_ip);
            sin_copy.sin_port = htons(target_port);
            return g_real_ConnectEx ? g_real_ConnectEx(s, (struct sockaddr*)&sin_copy, sizeof(sin_copy), lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped) : FALSE;
        } else if (strcmp(ip, "127.0.0.1") != 0 && strcmp(ip, "0.0.0.0") != 0) {
            LogMsg("[AirGap-BLOCKED] Denied ConnectEx to %s:%d", ip, port);
            WSASetLastError(WSAECONNREFUSED);
            return FALSE;
        }
    }
    return g_real_ConnectEx ? g_real_ConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped) : FALSE;
}

typedef int (WSAAPI *WSAIoctl_t)(
    SOCKET s, DWORD dwIoControlCode, LPVOID lpvInBuffer, DWORD cbInBuffer,
    LPVOID lpvOutBuffer, DWORD cbOutBuffer, LPDWORD lpcbBytesReturned,
    LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);
static WSAIoctl_t g_real_WSAIoctl = NULL;
static int WSAAPI Hook_WSAIoctl(
    SOCKET s, DWORD dwIoControlCode, LPVOID lpvInBuffer, DWORD cbInBuffer,
    LPVOID lpvOutBuffer, DWORD cbOutBuffer, LPDWORD lpcbBytesReturned,
    LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
    int res = g_real_WSAIoctl ? g_real_WSAIoctl(s, dwIoControlCode, lpvInBuffer, cbInBuffer, lpvOutBuffer, cbOutBuffer, lpcbBytesReturned, lpOverlapped, lpCompletionRoutine) : SOCKET_ERROR;
    if (dwIoControlCode == SIO_GET_EXTENSION_FUNCTION_POINTER && lpvInBuffer && cbInBuffer >= sizeof(GUID)) {
        GUID* guid = (GUID*)lpvInBuffer;
        if (memcmp(guid, &g_WSAID_CONNECTEX, sizeof(GUID)) == 0 && lpvOutBuffer && cbOutBuffer >= sizeof(void*)) {
            LogMsg("[WSAIoctl] App queried ConnectEx function pointer! Hooking ConnectEx");
            g_real_ConnectEx = *(ConnectEx_t*)lpvOutBuffer;
            *(ConnectEx_t*)lpvOutBuffer = Hook_ConnectEx;
        }
    }
    return res;
}

typedef int (WSAAPI *sendto_t)(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen);
static sendto_t g_real_sendto = NULL;
static int WSAAPI Hook_sendto(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen) {
    void* caller = _ReturnAddress();
    if (to) {
        if (to->sa_family == AF_INET) {
            struct sockaddr_in* sin = (struct sockaddr_in*)to;
            char ip[32] = {0};
            inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
            uint16_t port = ntohs(sin->sin_port);
            LogMsg("[UDP] sendto(IPv4) to %s:%u (len=%d, socket=%lld, caller=%p)", ip, port, len, (long long)s, caller);
            if (strcmp(ip, "127.0.0.1") != 0 && strcmp(ip, "0.0.0.0") != 0) {
                struct sockaddr_in sin_redir;
                memcpy(&sin_redir, to, sizeof(sin_redir));
                sin_redir.sin_addr.s_addr = inet_addr(g_server_ip);
                uint16_t redir_port = (port >= 27015 && port <= 27150) ? 27015 : ((port == 7777) ? 7777 : port);
                sin_redir.sin_port = htons(redir_port);
                LogMsg("[Egress] Redirecting UDP sendto(IPv4) from %s:%u to %s:%u", ip, port, g_server_ip, redir_port);
                return g_real_sendto ? g_real_sendto(s, buf, len, flags, (struct sockaddr*)&sin_redir, tolen) : SOCKET_ERROR;
            }
        } else if (to->sa_family == AF_INET6) {
            struct sockaddr_in6* sin6 = (struct sockaddr_in6*)to;
            char ip6[64] = {0};
            inet_ntop(AF_INET6, &sin6->sin6_addr, ip6, sizeof(ip6));
            uint16_t port = ntohs(sin6->sin6_port);
            LogMsg("[UDP] sendto(IPv6) to [%s]:%u (len=%d, socket=%lld, caller=%p)", ip6, port, len, (long long)s, caller);
            if (strcmp(ip6, "::1") != 0 && strcmp(ip6, "::") != 0) {
                struct sockaddr_in6 sin6_redir;
                memcpy(&sin6_redir, to, sizeof(sin6_redir));
                memset(&sin6_redir.sin6_addr, 0, sizeof(sin6_redir.sin6_addr));
                sin6_redir.sin6_addr.s6_addr[15] = 1;
                uint16_t redir_port = (port >= 27015 && port <= 27150) ? 27015 : ((port == 7777) ? 7777 : port);
                sin6_redir.sin6_port = htons(redir_port);
                LogMsg("[Egress] Redirecting UDP sendto(IPv6) from [%s]:%u to [::1]:%u", ip6, port, redir_port);
                return g_real_sendto ? g_real_sendto(s, buf, len, flags, (struct sockaddr*)&sin6_redir, tolen) : SOCKET_ERROR;
            }
        }
    }
    return g_real_sendto ? g_real_sendto(s, buf, len, flags, to, tolen) : SOCKET_ERROR;
}

typedef int (WSAAPI *WSASendTo_t)(
    SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent,
    DWORD dwFlags, const struct sockaddr* lpTo, int iTolen,
    LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);
static WSASendTo_t g_real_WSASendTo = NULL;
static int WSAAPI Hook_WSASendTo(
    SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent,
    DWORD dwFlags, const struct sockaddr* lpTo, int iTolen,
    LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
    void* caller = _ReturnAddress();
    if (lpTo) {
        if (lpTo->sa_family == AF_INET) {
            struct sockaddr_in* sin = (struct sockaddr_in*)lpTo;
            char ip[32] = {0};
            inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
            uint16_t port = ntohs(sin->sin_port);
            LogMsg("[UDP] WSASendTo(IPv4) to %s:%u (socket=%lld, caller=%p)", ip, port, (long long)s, caller);
            if (strcmp(ip, "127.0.0.1") != 0 && strcmp(ip, "0.0.0.0") != 0) {
                struct sockaddr_in sin_redir;
                memcpy(&sin_redir, lpTo, sizeof(sin_redir));
                sin_redir.sin_addr.s_addr = inet_addr(g_server_ip);
                uint16_t redir_port = (port >= 27015 && port <= 27150) ? 27015 : ((port == 7777) ? 7777 : port);
                sin_redir.sin_port = htons(redir_port);
                LogMsg("[Egress] Redirecting WSASendTo(IPv4) from %s:%u to %s:%u", ip, port, g_server_ip, redir_port);
                return g_real_WSASendTo ? g_real_WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, (struct sockaddr*)&sin_redir, iTolen, lpOverlapped, lpCompletionRoutine) : SOCKET_ERROR;
            }
        } else if (lpTo->sa_family == AF_INET6) {
            struct sockaddr_in6* sin6 = (struct sockaddr_in6*)lpTo;
            char ip6[64] = {0};
            inet_ntop(AF_INET6, &sin6->sin6_addr, ip6, sizeof(ip6));
            uint16_t port = ntohs(sin6->sin6_port);
            LogMsg("[UDP] WSASendTo(IPv6) to [%s]:%u (socket=%lld, caller=%p)", ip6, port, (long long)s, caller);
            if (strcmp(ip6, "::1") != 0 && strcmp(ip6, "::") != 0) {
                struct sockaddr_in6 sin6_redir;
                memcpy(&sin6_redir, lpTo, sizeof(sin6_redir));
                memset(&sin6_redir.sin6_addr, 0, sizeof(sin6_redir.sin6_addr));
                sin6_redir.sin6_addr.s6_addr[15] = 1;
                uint16_t redir_port = (port >= 27015 && port <= 27150) ? 27015 : ((port == 7777) ? 7777 : port);
                sin6_redir.sin6_port = htons(redir_port);
                LogMsg("[Egress] Redirecting WSASendTo(IPv6) from [%s]:%u to [::1]:%u", ip6, port, redir_port);
                return g_real_WSASendTo ? g_real_WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, (struct sockaddr*)&sin6_redir, iTolen, lpOverlapped, lpCompletionRoutine) : SOCKET_ERROR;
            }
        }
    }
    return g_real_WSASendTo ? g_real_WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iTolen, lpOverlapped, lpCompletionRoutine) : SOCKET_ERROR;
}

static int WSAAPI Hook_connect(SOCKET s, const struct sockaddr* name, int namelen);
static int WSAAPI Hook_WSAConnect(SOCKET s, const struct sockaddr *name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS);
static int WSAAPI Hook_getaddrinfo(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA *pHints, PADDRINFOA *ppResult);
static int WSAAPI Hook_GetAddrInfoW(PCWSTR pNodeName, PCWSTR pServiceName, const ADDRINFOW *pHints, PADDRINFOW *ppResult);
static INT WSAAPI Hook_GetAddrInfoExW(PCWSTR pName, PCWSTR pServiceName, DWORD dwNamespace, LPGUID lpNspId, const ADDRINFOEXW *pHints, PADDRINFOEXW *ppResult, struct timeval *timeout, LPOVERLAPPED lpOverlapped, LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine, LPHANDLE lpNameHandle);
static HINTERNET WINAPI Hook_WinHttpConnect(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved);
static HINTERNET WINAPI Hook_WinHttpOpenRequest(HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR *ppwszAcceptTypes, DWORD dwFlags);
static BOOL WINAPI Hook_WinHttpSendRequest(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext);
static BOOL WINAPI Hook_WinHttpReceiveResponse(HINTERNET hRequest, LPVOID lpReserved);
static HANDLE WINAPI Hook_CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
static HANDLE WINAPI Hook_CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
static BOOL WINAPI Hook_WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);

typedef FARPROC (WINAPI *GetProcAddress_t)(HMODULE hModule, LPCSTR lpProcName);
static GetProcAddress_t g_real_GetProcAddress = NULL;
static FARPROC WINAPI Hook_GetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
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
        } else if (strcmp(lpProcName, "WinHttpConnect") == 0) {
            LogMsg("[GetProcAddress] Dynamic lookup: WinHttpConnect -> hooked");
            return (FARPROC)Hook_WinHttpConnect;
        } else if (strcmp(lpProcName, "WinHttpOpenRequest") == 0) {
            LogMsg("[GetProcAddress] Dynamic lookup: WinHttpOpenRequest -> hooked");
            return (FARPROC)Hook_WinHttpOpenRequest;
        } else if (strcmp(lpProcName, "WinHttpSendRequest") == 0) {
            LogMsg("[GetProcAddress] Dynamic lookup: WinHttpSendRequest -> hooked");
            return (FARPROC)Hook_WinHttpSendRequest;
        } else if (strcmp(lpProcName, "WinHttpReceiveResponse") == 0) {
            LogMsg("[GetProcAddress] Dynamic lookup: WinHttpReceiveResponse -> hooked");
            return (FARPROC)Hook_WinHttpReceiveResponse;
        } else if (strcmp(lpProcName, "CreateFileW") == 0) {
            LogMsg("[GetProcAddress] Dynamic lookup: CreateFileW -> hooked");
            return (FARPROC)Hook_CreateFileW;
        } else if (strcmp(lpProcName, "CreateFileA") == 0) {
            LogMsg("[GetProcAddress] Dynamic lookup: CreateFileA -> hooked");
            return (FARPROC)Hook_CreateFileA;
        } else if (strcmp(lpProcName, "WriteFile") == 0) {
            LogMsg("[GetProcAddress] Dynamic lookup: WriteFile -> hooked");
            return (FARPROC)Hook_WriteFile;
        }
    } else {
        uint16_t ord = (uint16_t)((uintptr_t)lpProcName & 0xFFFF);
        if (ord == 4) {
            LogMsg("[GetProcAddress] Dynamic lookup: ord(4) -> connect hooked");
            return (FARPROC)Hook_connect;
        }
    }
    return realProc;
}
typedef int (WSAAPI *connect_t)(SOCKET s, const struct sockaddr* name, int namelen);
static connect_t g_real_connect = NULL;
static int WSAAPI Hook_connect(SOCKET s, const struct sockaddr* name, int namelen) {
    if (name) {
        if (name->sa_family == AF_INET) {
            struct sockaddr_in sin_copy;
            memcpy(&sin_copy, name, sizeof(sin_copy));
            uint16_t port = ntohs(sin_copy.sin_port);
            char ip[32] = {0};
            inet_ntop(AF_INET, &sin_copy.sin_addr, ip, sizeof(ip));
            LogMsg("[TCP] connect(IPv4) to %s:%d (socket=%lld)", ip, port, (long long)s);
            if (port == 443 || port == 80 || (strcmp(ip, "127.0.0.1") != 0 && (port == 8080 || port == 7777))) {
                uint16_t target_port = (port == 80) ? 80 : ((port == 443) ? 443 : ((port == 7777) ? 7777 : (uint16_t)atoi(g_server_port)));
                LogMsg("[Egress] Redirecting IPv4 connect() from %s:%d to %s:%u",
                       ip, port, g_server_ip, target_port);
                sin_copy.sin_addr.s_addr = inet_addr(g_server_ip);
                sin_copy.sin_port = htons(target_port);
                return g_real_connect ? g_real_connect(s, (struct sockaddr*)&sin_copy, sizeof(sin_copy)) : SOCKET_ERROR;
            }

        } else if (name->sa_family == AF_INET6) {
            struct sockaddr_in6 sin6_copy;
            memcpy(&sin6_copy, name, sizeof(sin6_copy));
            uint16_t port = ntohs(sin6_copy.sin6_port);
            char ip6[64] = {0};
            inet_ntop(AF_INET6, &sin6_copy.sin6_addr, ip6, sizeof(ip6));
            LogMsg("[TCP] connect(IPv6) to [%s]:%d (socket=%lld)", ip6, port, (long long)s);
            if (port == 443 || port == 80 || port == 8080 || port == 7777) {
                uint16_t target_port = (port == 80) ? 80 : ((port == 443) ? 443 : ((port == 7777) ? 7777 : (uint16_t)atoi(g_server_port)));
                LogMsg("[Egress] Redirecting IPv6 connect() to [::1]:%u", target_port);
                memset(&sin6_copy.sin6_addr, 0, sizeof(sin6_copy.sin6_addr));
                sin6_copy.sin6_addr.s6_addr[15] = 1;
                sin6_copy.sin6_port = htons(target_port);
                return g_real_connect ? g_real_connect(s, (struct sockaddr*)&sin6_copy, sizeof(sin6_copy)) : SOCKET_ERROR;
            }

        } else {
            LogMsg("[TCP] connect(family=%d)", name->sa_family);
        }

    }

    return g_real_connect ? g_real_connect(s, name, namelen) : SOCKET_ERROR;
}

typedef int (WSAAPI *WSAConnect_t)(
    SOCKET s,
    const struct sockaddr *name,
    int namelen,
    LPWSABUF lpCallerData,
    LPWSABUF lpCalleeData,
    LPQOS lpSQOS,
    LPQOS lpGQOS
);
static WSAConnect_t g_real_WSAConnect = NULL;
static int WSAAPI Hook_WSAConnect(
    SOCKET s,
    const struct sockaddr *name,
    int namelen,
    LPWSABUF lpCallerData,
    LPWSABUF lpCalleeData,
    LPQOS lpSQOS,
    LPQOS lpGQOS
) {
    if (name && name->sa_family == AF_INET) {
        struct sockaddr_in sin_copy;
        memcpy(&sin_copy, name, sizeof(sin_copy));
        uint16_t port = ntohs(sin_copy.sin_port);
        char ip[32] = {0};
        inet_ntop(AF_INET, &sin_copy.sin_addr, ip, sizeof(ip));
        LogMsg("[TCP] WSAConnect(IPv4) to %s:%d", ip, port);
        if (port == 443 || port == 80 || (strcmp(ip, "127.0.0.1") != 0 && (port == 8080 || port == 7777))) {
            uint16_t target_port = (port == 80) ? 80 : ((port == 443) ? 443 : ((port == 7777) ? 7777 : (uint16_t)atoi(g_server_port)));
            LogMsg("[Egress] Redirecting IPv4 WSAConnect() from %s:%d to %s:%u",
                   ip, port, g_server_ip, target_port);
            sin_copy.sin_addr.s_addr = inet_addr(g_server_ip);
            sin_copy.sin_port = htons(target_port);
            return g_real_WSAConnect ? g_real_WSAConnect(s, (struct sockaddr*)&sin_copy, sizeof(sin_copy), lpCallerData, lpCalleeData, lpSQOS, lpGQOS) : SOCKET_ERROR;
        }

    }

    return g_real_WSAConnect ? g_real_WSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS) : SOCKET_ERROR;
}

typedef HINTERNET (WINAPI *WinHttpConnect_t)(
    HINTERNET hSession,
    LPCWSTR pswzServerName,
    INTERNET_PORT nServerPort,
    DWORD dwReserved
);
static WinHttpConnect_t g_real_WinHttpConnect = NULL;
static HINTERNET WINAPI Hook_WinHttpConnect(
    HINTERNET hSession,
    LPCWSTR pswzServerName,
    INTERNET_PORT nServerPort,
    DWORD dwReserved
) {
    if (pswzServerName) {
        char sNameA[256] = { 0 };
        WideCharToMultiByte(CP_UTF8, 0, pswzServerName, -1, sNameA, sizeof(sNameA), NULL, NULL);
        LogMsg("[WinHTTP] WinHttpConnect(server='%s', port=%u)", sNameA, (unsigned int)nServerPort);
        if (strstr(sNameA, "deadorbit") || strstr(sNameA, "bungie") || strstr(sNameA, "goliath") || strstr(sNameA, "playfab") || strstr(sNameA, "gravityshavings") || (strcmp(sNameA, "127.0.0.1") != 0 && strcmp(sNameA, "localhost") != 0)) {
            uint16_t target_port = (nServerPort == 80) ? 80 : ((nServerPort == 443) ? 443 : ((nServerPort == 7777) ? 7777 : (uint16_t)atoi(g_server_port)));
            LogMsg("[Egress] Redirecting WinHttpConnect from '%s:%u' to 127.0.0.1:%u", sNameA, (unsigned int)nServerPort, target_port);
            return g_real_WinHttpConnect ? g_real_WinHttpConnect(hSession, L"127.0.0.1", (INTERNET_PORT)target_port, dwReserved) : NULL;
        }

    }

    return g_real_WinHttpConnect ? g_real_WinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved) : NULL;
}

typedef HINTERNET (WINAPI *WinHttpOpenRequest_t)(
    HINTERNET hConnect,
    LPCWSTR pwszVerb,
    LPCWSTR pwszObjectName,
    LPCWSTR pwszVersion,
    LPCWSTR pwszReferrer,
    LPCWSTR *ppwszAcceptTypes,
    DWORD dwFlags
);
static WinHttpOpenRequest_t g_real_WinHttpOpenRequest = NULL;
static HINTERNET WINAPI Hook_WinHttpOpenRequest(
    HINTERNET hConnect,
    LPCWSTR pwszVerb,
    LPCWSTR pwszObjectName,
    LPCWSTR pwszVersion,
    LPCWSTR pwszReferrer,
    LPCWSTR *ppwszAcceptTypes,
    DWORD dwFlags
) {
    char objA[256] = { 0 };
    if (pwszObjectName) WideCharToMultiByte(CP_UTF8, 0, pwszObjectName, -1, objA, sizeof(objA), NULL, NULL);
    LogMsg("[WinHTTP] WinHttpOpenRequest(object='%s', flags=0x%lx)", objA, dwFlags);
    HINTERNET hReq = g_real_WinHttpOpenRequest ?
        g_real_WinHttpOpenRequest(hConnect, pwszVerb, pwszObjectName, pwszVersion, pwszReferrer, ppwszAcceptTypes, dwFlags) : NULL;
    if (hReq) {
        DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                         SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                         SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                         SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
        LogMsg("[WinHTTP] Applied SECURITY_FLAG_IGNORE_UNKNOWN_CA to request %p", hReq);
    }

    return hReq;
}

typedef BOOL (WINAPI *WinHttpSendRequest_t)(
    HINTERNET hRequest,
    LPCWSTR lpszHeaders,
    DWORD dwHeadersLength,
    LPVOID lpOptional,
    DWORD dwOptionalLength,
    DWORD dwTotalLength,
    DWORD_PTR dwContext
);
static WinHttpSendRequest_t g_real_WinHttpSendRequest = NULL;
static BOOL WINAPI Hook_WinHttpSendRequest(
    HINTERNET hRequest,
    LPCWSTR lpszHeaders,
    DWORD dwHeadersLength,
    LPVOID lpOptional,
    DWORD dwOptionalLength,
    DWORD dwTotalLength,
    DWORD_PTR dwContext
) {
    if (!g_real_WinHttpSendRequest) {
        HMODULE hWinHttp = GetModuleHandleA("WINHTTP.dll");
        if (!hWinHttp) hWinHttp = LoadLibraryA("WINHTTP.dll");
        if (hWinHttp) g_real_WinHttpSendRequest = (WinHttpSendRequest_t)GetProcAddress(hWinHttp, "WinHttpSendRequest");
    }
    char hdrA[256] = {0};
    if (lpszHeaders && dwHeadersLength > 0 && dwHeadersLength < sizeof(hdrA)) {
        WideCharToMultiByte(CP_UTF8, 0, lpszHeaders, dwHeadersLength, hdrA, sizeof(hdrA) - 1, NULL, NULL);
    }
    LogMsg("[WinHTTP] WinHttpSendRequest(hReq=%p, optLen=%lu, totLen=%lu, hdr='%s')", hRequest, dwOptionalLength, dwTotalLength, hdrA);
    BOOL res = g_real_WinHttpSendRequest ?
        g_real_WinHttpSendRequest(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext) : FALSE;
    if (!res) {
        DWORD err = GetLastError();
        LogMsg("[WinHTTP] WinHttpSendRequest FAILED, GetLastError() = %lu (0x%lX)", err, err);
    } else {
        LogMsg("[WinHTTP] WinHttpSendRequest SUCCEEDED");
    }
    return res;
}

typedef BOOL (WINAPI *WinHttpReceiveResponse_t)(
    HINTERNET hRequest,
    LPVOID lpReserved
);
static WinHttpReceiveResponse_t g_real_WinHttpReceiveResponse = NULL;
static BOOL WINAPI Hook_WinHttpReceiveResponse(
    HINTERNET hRequest,
    LPVOID lpReserved
) {
    if (!g_real_WinHttpReceiveResponse) {
        HMODULE hWinHttp = GetModuleHandleA("WINHTTP.dll");
        if (!hWinHttp) hWinHttp = LoadLibraryA("WINHTTP.dll");
        if (hWinHttp) g_real_WinHttpReceiveResponse = (WinHttpReceiveResponse_t)GetProcAddress(hWinHttp, "WinHttpReceiveResponse");
    }
    LogMsg("[WinHTTP] WinHttpReceiveResponse(hReq=%p)", hRequest);
    BOOL res = g_real_WinHttpReceiveResponse ?
        g_real_WinHttpReceiveResponse(hRequest, lpReserved) : FALSE;
    if (!res) {
        DWORD err = GetLastError();
        LogMsg("[WinHTTP] WinHttpReceiveResponse FAILED, GetLastError() = %lu (0x%lX)", err, err);
    } else {
        DWORD statusCode = 0;
        DWORD statusSize = sizeof(statusCode);
        if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX)) {
            LogMsg("[WinHTTP] WinHttpReceiveResponse SUCCEEDED, HTTP Status = %lu", statusCode);
        } else {
            LogMsg("[WinHTTP] WinHttpReceiveResponse SUCCEEDED");
        }
    }
    return res;
}

// ---------------------------------------------------------------------------

// VFS & File Logging Hooks (KERNEL32!CreateFileW, CreateFileA)

// ---------------------------------------------------------------------------

typedef HANDLE (WINAPI *CreateFileW_t)(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
);
static CreateFileW_t g_real_CreateFileW = NULL;
typedef HANDLE (WINAPI *CreateFileA_t)(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
);
static CreateFileA_t g_real_CreateFileA = NULL;

typedef BOOL (WINAPI *WriteFile_t)(
    HANDLE hFile,
    LPCVOID lpBuffer,
    DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
);
static WriteFile_t g_real_WriteFile = NULL;

static HANDLE WINAPI Hook_CreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
) {
    HANDLE h = g_real_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    DWORD err = (h == INVALID_HANDLE_VALUE) ? GetLastError() : 0;
    char mbPath[MAX_PATH * 2] = {0};
    if (lpFileName) {
        WideCharToMultiByte(CP_UTF8, 0, lpFileName, -1, mbPath, sizeof(mbPath) - 1, NULL, NULL);
    }

    if (mbPath[0]) {
        if (strstr(mbPath, "lmdetail") || strstr(mbPath, "direct_settings") || strstr(mbPath, "global.json")) {
            void* caller = _ReturnAddress();
            LogMsg("[File-Target] CreateFileW('%s') -> handle %p (err=%lu, caller=%p)", mbPath, h, err, caller);
            void* stack[8];
            USHORT frames = RtlCaptureStackBackTrace(0, 8, stack, NULL);
            for (USHORT f = 0; f < frames; f++) {
                LogCallerInfo("File-Target-Stack", stack[f]);
            }
        }
    }

    if (h == INVALID_HANDLE_VALUE) {
        if (mbPath[0] && !strstr(mbPath, "pipe\\") && !strstr(mbPath, "GLOBALROOT") && !strstr(mbPath, "NUL")) {
            LogMsg("[File-FAIL] CreateFileW('%s') -> INVALID_HANDLE_VALUE (err=%lu)", mbPath, err);
        }

        SetLastError(err);
    } else {
        if (mbPath[0] && (strstr(mbPath, ".pkg") || strstr(mbPath, "packages") || strstr(mbPath, "handle_map") || strstr(mbPath, "cache") || strstr(mbPath, "sku_config") || strstr(mbPath, ".bin") || strstr(mbPath, ".json") || strstr(mbPath, ".txt"))) {
            LogMsg("[File-OK] CreateFileW('%s') -> handle %p", mbPath, h);
        }

    }

    return h;
}

static HANDLE WINAPI Hook_CreateFileA(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
) {
    HANDLE h = g_real_CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    DWORD err = (h == INVALID_HANDLE_VALUE) ? GetLastError() : 0;
    if (h == INVALID_HANDLE_VALUE) {
        if (lpFileName && !strstr(lpFileName, "pipe\\") && !strstr(lpFileName, "NUL")) {
            LogMsg("[File-FAIL] CreateFileA('%s') -> INVALID_HANDLE_VALUE (err=%lu)", lpFileName, err);
        }

        SetLastError(err);
    } else {
        if (lpFileName && (strstr(lpFileName, ".pkg") || strstr(lpFileName, "packages") || strstr(lpFileName, "handle_map") || strstr(lpFileName, "cache") || strstr(lpFileName, "sku_config") || strstr(lpFileName, ".bin") || strstr(lpFileName, ".json") || strstr(lpFileName, ".txt"))) {
            LogMsg("[File-OK] CreateFileA('%s') -> handle %p", lpFileName, h);
        }

    }

    return h;
}

static BOOL WINAPI Hook_WriteFile(
    HANDLE hFile,
    LPCVOID lpBuffer,
    DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
) {
    if (lpBuffer && nNumberOfBytesToWrite > 0) {
        const char* buf = (const char*)lpBuffer;
        if (strstr(buf, "platform_account_id") || strstr(buf, "session_id") || strstr(buf, "state_duration") || strstr(buf, "lmdetail")) {
            void* caller = _ReturnAddress();
            char preview[300] = {0};
            int len = (int)(nNumberOfBytesToWrite < 250 ? nNumberOfBytesToWrite : 250);
            memcpy(preview, buf, len);
            LogMsg("[File-WriteFile] lmdetail buffer written! caller=%p, bytes=%u: %s", caller, nNumberOfBytesToWrite, preview);
            void* stack[8];
            USHORT frames = RtlCaptureStackBackTrace(0, 8, stack, NULL);
            for (USHORT f = 0; f < frames; f++) {
                LogCallerInfo("lmdetail-WriteFile-Stack", stack[f]);
            }
        }
    }
    return g_real_WriteFile ? g_real_WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped) : FALSE;
}

static void HookModuleIAT(HMODULE hMod, const char* targetModName) {
    if (!hMod) return;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((uint8_t*)hMod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    IMAGE_DATA_DIRECTORY importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress == 0 || importDir.Size == 0) return;
    PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)((uint8_t*)hMod + importDir.VirtualAddress);
    while (pImport->Name) {
        const char* modName = (const char*)((uint8_t*)hMod + pImport->Name);
        bool isWs2 = (_stricmp(modName, "WS2_32.dll") == 0);
        bool isK32 = (_stricmp(modName, "KERNEL32.dll") == 0);
        bool isCrypt = (_stricmp(modName, "CRYPT32.dll") == 0);
        bool isWinHttp = (_stricmp(modName, "WINHTTP.dll") == 0);
        if (isWs2 || isK32 || isCrypt || isWinHttp) {
            uint32_t iltRVA = pImport->OriginalFirstThunk ? pImport->OriginalFirstThunk : pImport->FirstThunk;
            PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)((uint8_t*)hMod + iltRVA);
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((uint8_t*)hMod + pImport->FirstThunk);
            while (origThunk->u1.AddressOfData && thunk->u1.Function) {
                void* hook = NULL;
                const char* hookName = NULL;
                if (isWs2) {
                    if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                        uint16_t ord = (uint16_t)(origThunk->u1.Ordinal & 0xFFFF);
                        if (ord == 4) { hook = (void*)Hook_connect; hookName = "connect (ord 4)"; }
                        else if (ord == 17) { hook = (void*)Hook_sendto; hookName = "sendto (ord 17)"; }
                        else if (ord == 46 || ord == 60) { hook = (void*)Hook_WSAConnect; hookName = "WSAConnect (ord 46/60)"; }
                        else if (ord == 52) { hook = (void*)Hook_gethostbyname; hookName = "gethostbyname (ord 52)"; }
                    } else {
                        PIMAGE_IMPORT_BY_NAME impName = (PIMAGE_IMPORT_BY_NAME)((uint8_t*)hMod + origThunk->u1.AddressOfData);
                        const char* name = (const char*)impName->Name;
                        if (strcmp(name, "connect") == 0) { hook = (void*)Hook_connect; hookName = "connect"; }
                        else if (strcmp(name, "WSAConnect") == 0) { hook = (void*)Hook_WSAConnect; hookName = "WSAConnect"; }
                        else if (strcmp(name, "WSAIoctl") == 0) { hook = (void*)Hook_WSAIoctl; hookName = "WSAIoctl"; }
                        else if (strcmp(name, "sendto") == 0) { hook = (void*)Hook_sendto; hookName = "sendto"; }
                        else if (strcmp(name, "WSASendTo") == 0) { hook = (void*)Hook_WSASendTo; hookName = "WSASendTo"; }
                        else if (strcmp(name, "getaddrinfo") == 0) { hook = (void*)Hook_getaddrinfo; hookName = "getaddrinfo"; }
                        else if (strcmp(name, "GetAddrInfoW") == 0) { hook = (void*)Hook_GetAddrInfoW; hookName = "GetAddrInfoW"; }
                        else if (strcmp(name, "GetAddrInfoExW") == 0) { hook = (void*)Hook_GetAddrInfoExW; hookName = "GetAddrInfoExW"; }
                        else if (strcmp(name, "gethostbyname") == 0) { hook = (void*)Hook_gethostbyname; hookName = "gethostbyname"; }
                    }
                } else if (isCrypt) {
                    if (!(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                        PIMAGE_IMPORT_BY_NAME impName = (PIMAGE_IMPORT_BY_NAME)((uint8_t*)hMod + origThunk->u1.AddressOfData);
                        const char* name = (const char*)impName->Name;
                        if (strcmp(name, "CertVerifyCertificateChainPolicy") == 0) { hook = (void*)Hook_CertVerifyCertificateChainPolicy; hookName = "CertVerifyCertificateChainPolicy"; }
                    }
                } else if (isK32) {
                    if (!(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                        PIMAGE_IMPORT_BY_NAME impName = (PIMAGE_IMPORT_BY_NAME)((uint8_t*)hMod + origThunk->u1.AddressOfData);
                        const char* name = (const char*)impName->Name;
                        if (strcmp(name, "CreateFileW") == 0) { hook = (void*)Hook_CreateFileW; hookName = "CreateFileW"; }
                        else if (strcmp(name, "CreateFileA") == 0) { hook = (void*)Hook_CreateFileA; hookName = "CreateFileA"; }
                        else if (strcmp(name, "WriteFile") == 0) { hook = (void*)Hook_WriteFile; hookName = "WriteFile"; }
                        else if (strcmp(name, "GetProcAddress") == 0) { hook = (void*)Hook_GetProcAddress; hookName = "GetProcAddress"; }
                    }
                } else if (isWinHttp) {
                    if (!(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                        PIMAGE_IMPORT_BY_NAME impName = (PIMAGE_IMPORT_BY_NAME)((uint8_t*)hMod + origThunk->u1.AddressOfData);
                        const char* name = (const char*)impName->Name;
                        if (strcmp(name, "WinHttpConnect") == 0) { hook = (void*)Hook_WinHttpConnect; hookName = "WinHttpConnect"; }

                        else if (strcmp(name, "WinHttpOpenRequest") == 0) { hook = (void*)Hook_WinHttpOpenRequest; hookName = "WinHttpOpenRequest"; }
                        else if (strcmp(name, "WinHttpSendRequest") == 0) { hook = (void*)Hook_WinHttpSendRequest; hookName = "WinHttpSendRequest"; }
                        else if (strcmp(name, "WinHttpReceiveResponse") == 0) { hook = (void*)Hook_WinHttpReceiveResponse; hookName = "WinHttpReceiveResponse"; }

                    }

                }

                if (hook && (void*)thunk->u1.Function != hook) {
                    DWORD oldProtect;
                    if (VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProtect)) {
                        thunk->u1.Function = (uintptr_t)hook;
                        VirtualProtect(&thunk->u1.Function, sizeof(void*), oldProtect, &oldProtect);
                        LogMsg("[%s] Successfully hooked %s!%s", targetModName, modName, hookName);
                    }

                }

                origThunk++;
                thunk++;
            }

        }

        pImport++;
    }

}


static bool g_partywin_hooked = false;
static bool g_libcurl_hooked = false;

static void CheckDynamicModules() {
    HMODULE hExe = GetModuleHandleA(NULL);
    if (hExe) {
        HookModuleIAT(hExe, "Marathon.exe");
    }
    if (!g_partywin_hooked) {
        HMODULE hParty = GetModuleHandleA("PartyWin.dll");
        if (hParty) {
            HookModuleIAT(hParty, "PartyWin.dll");
            g_partywin_hooked = true;
        }
    }
    if (!g_libcurl_hooked) {
        HMODULE hCurl = GetModuleHandleA("libcurl.dll");
        if (hCurl) {
            HookModuleIAT(hCurl, "libcurl.dll");
            g_libcurl_hooked = true;
        }
    }
}

static void InstallIATHooks() {
    HMODULE hWs2 = GetModuleHandleA("WS2_32.dll");
    if (!hWs2) hWs2 = LoadLibraryA("WS2_32.dll");
    if (hWs2) {
        g_real_getaddrinfo = (getaddrinfo_t)GetProcAddress(hWs2, "getaddrinfo");
        g_real_GetAddrInfoW = (GetAddrInfoW_t)GetProcAddress(hWs2, "GetAddrInfoW");
        g_real_GetAddrInfoExW = (GetAddrInfoExW_t)GetProcAddress(hWs2, "GetAddrInfoExW");
        g_real_gethostbyname = (gethostbyname_t)GetProcAddress(hWs2, "gethostbyname");
        g_real_connect = (connect_t)GetProcAddress(hWs2, "connect");
        g_real_WSAConnect = (WSAConnect_t)GetProcAddress(hWs2, "WSAConnect");
        g_real_WSAIoctl = (WSAIoctl_t)GetProcAddress(hWs2, "WSAIoctl");
        g_real_sendto = (sendto_t)GetProcAddress(hWs2, "sendto");
        g_real_WSASendTo = (WSASendTo_t)GetProcAddress(hWs2, "WSASendTo");
    }

    HMODULE hCrypt = GetModuleHandleA("CRYPT32.dll");
    if (!hCrypt) hCrypt = LoadLibraryA("CRYPT32.dll");
    if (hCrypt) {
        g_real_CertVerifyCertificateChainPolicy = (CertVerifyCertificateChainPolicy_t)GetProcAddress(hCrypt, "CertVerifyCertificateChainPolicy");
    }

    HMODULE hWinHttp = GetModuleHandleA("WINHTTP.dll");
    if (!hWinHttp) hWinHttp = LoadLibraryA("WINHTTP.dll");
    if (hWinHttp) {
        g_real_WinHttpConnect = (WinHttpConnect_t)GetProcAddress(hWinHttp, "WinHttpConnect");
        g_real_WinHttpOpenRequest = (WinHttpOpenRequest_t)GetProcAddress(hWinHttp, "WinHttpOpenRequest");
        g_real_WinHttpSendRequest = (WinHttpSendRequest_t)GetProcAddress(hWinHttp, "WinHttpSendRequest");
        g_real_WinHttpReceiveResponse = (WinHttpReceiveResponse_t)GetProcAddress(hWinHttp, "WinHttpReceiveResponse");
    }

    HMODULE hK32 = GetModuleHandleA("KERNEL32.dll");
    if (!hK32) hK32 = LoadLibraryA("KERNEL32.dll");
    if (hK32) {
        g_real_GetProcAddress = (GetProcAddress_t)GetProcAddress(hK32, "GetProcAddress");
        g_real_CreateFileW = (CreateFileW_t)GetProcAddress(hK32, "CreateFileW");
        g_real_CreateFileA = (CreateFileA_t)GetProcAddress(hK32, "CreateFileA");
        g_real_WriteFile = (WriteFile_t)GetProcAddress(hK32, "WriteFile");
    }

    CheckDynamicModules();
}

// ---------------------------------------------------------------------------

// Configuration Loader

// ---------------------------------------------------------------------------

static void LoadConfig() {
    char iniPath[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, iniPath);
    strcat(iniPath, "\\marathon_client.ini");
    GetPrivateProfileStringA("Server", "ServerIP", "127.0.0.1", g_server_ip, sizeof(g_server_ip), iniPath);
    GetPrivateProfileStringA("Server", "ServerPort", "8080", g_server_port, sizeof(g_server_port), iniPath);
    GetPrivateProfileStringA("Player", "PlayerName", "Runner", g_player_name, sizeof(g_player_name), iniPath);
    char steamIdStr[64];
    GetPrivateProfileStringA("Player", "SteamID", "76561198000001001", steamIdStr, sizeof(steamIdStr), iniPath);
    g_steam_id = _strtoui64(steamIdStr, NULL, 10);
    LogMsg("[Config] Loaded marathon_client.ini -> IP: %s, Port: %s, Player: %s, SteamID: %llu",
           g_server_ip, g_server_port, g_player_name, g_steam_id);
}

// ---------------------------------------------------------------------------

// DllMain Entry Point

// ---------------------------------------------------------------------------

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        InitLogPath(hinstDLL);
        LogMsg("==================================================");
        LogMsg(" Marathon Standalone Client Proxy (Project Dawn)  ");
        LogMsg(" Target Build: 26136895 (Cryo Archive Vault Breaker)");
        LogMsg(" Log file active at: %s", g_log_path);
        LogMsg("==================================================");
        LoadConfig();
        InitInterfaceTables();
        InstallIATHooks();
        if (InterlockedCompareExchange(&g_bootflow_hooks_installed, 1, 0) == 0) {
            InstallBootflowHooks();
        }
    }

    return TRUE;
}
