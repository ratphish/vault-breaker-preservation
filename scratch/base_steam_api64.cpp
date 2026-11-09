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
#include <ctype.h>

#pragma comment(lib, "ws2_32.lib")

// Configuration Defaults
static char g_server_ip[64] = "127.0.0.1";
static char g_server_port[16] = "8080";
static char g_player_name[64] = "Runner";
static uint64_t g_steam_id = 76561198000001001ULL;
static uint32_t g_app_id = 3065800; // Marathon Steam AppID

static void LogMsg(const char* fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    OutputDebugStringA(buf);
    
    FILE* fp = fopen("marathon_proxy.log", "a");
    if (fp) {
        fputs(buf, fp);
        fputc('\n', fp);
        fflush(fp); // Flush immediately to capture any crash
        fclose(fp);
    }
}

// ---------------------------------------------------------------------------
// Vectored Exception Handler to intercept & log crashes immediately
// ---------------------------------------------------------------------------
static LONG WINAPI VectoredCrashHandler(PEXCEPTION_POINTERS pExceptionInfo) {
    if (pExceptionInfo && pExceptionInfo->ExceptionRecord) {
        DWORD code = pExceptionInfo->ExceptionRecord->ExceptionCode;
        if (code == EXCEPTION_ACCESS_VIOLATION || 
            code == EXCEPTION_ILLEGAL_INSTRUCTION || 
            code == EXCEPTION_STACK_OVERFLOW ||
            code == 0xE06D7363 /* C++ Exception */) {
            LogMsg("[CRASH-ALERT] Code: 0x%08X at Address: %p", 
                   code, pExceptionInfo->ExceptionRecord->ExceptionAddress);
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// Case-insensitive substring search
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
static int64_t MethodReturnZero(void* self, ...) { return 0; }
static int64_t MethodReturnOne(void* self, ...) { return 1; }

static void* g_generic_vtable[128];
static InterfaceObject g_generic_interface = { g_generic_vtable };

// ISteamUser023
static uint32_t SteamUser_GetHSteamUser(void* self) { 
    LogMsg("[SteamUser] GetHSteamUser called");
    return 1; 
}
static int SteamUser_BLoggedOn(void* self) { 
    LogMsg("[SteamUser] BLoggedOn called -> 1");
    return 1; 
}
static uint64_t SteamUser_GetSteamID(void* self) { 
    LogMsg("[SteamUser] GetSteamID called -> %llu", g_steam_id);
    return g_steam_id; 
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
static uint64_t SteamUser_RequestEncryptedAppTicket(void* self, void* pDataToInclude, int cbDataToInclude) {
    LogMsg("[SteamUser] RequestEncryptedAppTicket called");
    return 1;
}
static int SteamUser_GetEncryptedAppTicket(void* self, void* pTicket, int cbMaxTicket, uint32_t* pcbTicket) {
    LogMsg("[SteamUser] GetEncryptedAppTicket called");
    if (pcbTicket) *pcbTicket = 0;
    return 1;
}
static int SteamUser_GetGameBadgeLevel(void* self, int nSeries, int bFoil) { return 1; }
static int SteamUser_GetPlayerSteamLevel(void* self) { return 1; }
static int SteamUser_BIsPhoneVerified(void* self) { return 1; }
static int SteamUser_BSetDurationControlOnlineState(void* self, int eNewState) { return 1; }

static void* g_user_vtable[64];
static InterfaceObject g_user_interface = { g_user_vtable };

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

static void* g_utils_vtable[64];
static InterfaceObject g_utils_interface = { g_utils_vtable };

// ISteamApps008
static int SteamApps_BIsSubscribed(void* self) { 
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
    LogMsg("[SteamApps] MarkContentCorrupt called");
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
        GetCurrentDirectoryA(cchFolderBufferSize, pchFolder);
        LogMsg("[SteamApps] -> install dir: %s", pchFolder);
        return (uint32_t)strlen(pchFolder);
    }
    return 0;
}
static int SteamApps_BIsAppInstalled(void* self, uint32_t nAppID) { 
    LogMsg("[SteamApps] BIsAppInstalled(%u) called -> 1", nAppID);
    return 1; 
}
static uint64_t SteamApps_GetAppOwner(void* self) { 
    LogMsg("[SteamApps] GetAppOwner called -> %llu", g_steam_id);
    return g_steam_id; 
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

static void* g_apps_vtable[64];
static InterfaceObject g_apps_interface = { g_apps_vtable };

// ISteamFriends017
static const char* SteamFriends_GetPersonaName(void* self) { 
    LogMsg("[SteamFriends] GetPersonaName called -> %s", g_player_name);
    return g_player_name; 
}
static uint64_t SteamFriends_SetPersonaName(void* self, const char* pchPersonaName) { return 0; }
static int SteamFriends_GetPersonaState(void* self) { return 1; }
static int SteamFriends_GetFriendCount(void* self, int iFriendFlags) { return 0; }
static uint64_t SteamFriends_GetFriendByIndex(void* self, int iFriend, int iFriendFlags) { return 0; }
static int SteamFriends_GetFriendRelationship(void* self, uint64_t steamIDFriend) { return 0; }
static int SteamFriends_GetFriendPersonaState(void* self, uint64_t steamIDFriend) { return 0; }
static const char* SteamFriends_GetFriendPersonaName(void* self, uint64_t steamIDFriend) { return ""; }
static int SteamFriends_GetFriendGamePlayed(void* self, uint64_t steamIDFriend, void* pFriendGameInfo) { return 0; }
static const char* SteamFriends_GetFriendPersonaNameHistory(void* self, uint64_t steamIDFriend, int iPersonaName) { return ""; }
static int SteamFriends_GetFriendSteamLevel(void* self, uint64_t steamIDFriend) { return 1; }
static const char* SteamFriends_GetPlayerNickname(void* self, uint64_t steamIDFriend) { return ""; }
static int SteamFriends_GetFriendsGroupCount(void* self) { return 0; }

static void* g_friends_vtable[80];
static InterfaceObject g_friends_interface = { g_friends_vtable };

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

static void* g_userstats_vtable[64];
static InterfaceObject g_userstats_interface = { g_userstats_vtable };

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

static void* g_input_vtable[64];
static InterfaceObject g_input_interface = { g_input_vtable };

static void InitInterfaceTables() {
    for (int i = 0; i < 128; i++) g_generic_vtable[i] = (void*)MethodReturnZero;
    for (int i = 0; i < 64; i++) g_user_vtable[i] = (void*)MethodReturnZero;
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
    g_user_vtable[16] = (void*)SteamUser_CancelAuthTicket;
    g_user_vtable[20] = (void*)SteamUser_RequestEncryptedAppTicket;
    g_user_vtable[21] = (void*)SteamUser_GetEncryptedAppTicket;
    g_user_vtable[22] = (void*)SteamUser_GetGameBadgeLevel;
    g_user_vtable[23] = (void*)SteamUser_GetPlayerSteamLevel;
    g_user_vtable[25] = (void*)SteamUser_BIsPhoneVerified;
    g_user_vtable[30] = (void*)SteamUser_BSetDurationControlOnlineState;

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
    LogMsg("[SteamAPI] SteamAPI_Shutdown called");
}

__declspec(dllexport) bool __cdecl SteamAPI_RestartAppIfNecessary(uint32_t unOwnAppID) {
    LogMsg("[SteamAPI] SteamAPI_RestartAppIfNecessary(%u) called -> FALSE (no restart needed)", unOwnAppID);
    return false;
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

__declspec(dllexport) void __cdecl SteamAPI_RegisterCallResult(void* pCallback, uint64_t hAPICall) {
    LogMsg("[SteamAPI] RegisterCallResult: call=%llu, ptr=%p", hAPICall, pCallback);
}

__declspec(dllexport) void __cdecl SteamAPI_UnregisterCallResult(void* pCallback, uint64_t hAPICall) {
}

__declspec(dllexport) void __cdecl SteamAPI_RunCallbacks() {
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

__declspec(dllexport) void* __cdecl SteamInternal_ContextInit(void* pContextInitData) {
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

__declspec(dllexport) int __cdecl SteamInternal_SteamAPI_Init(const char* pszExplicitOptIn, void* pError) {
    LogMsg("[SteamAPI] SteamInternal_SteamAPI_Init called -> SUCCESS (k_ESteamAPIInitResult_OK = 0)");
    if (pError) {
        *(char*)pError = '\0';
    }
    return 0; // 0 == k_ESteamAPIInitResult_OK
}

} // extern "C"

// ---------------------------------------------------------------------------
// Network Egress Hooking (IAT Hooks for WS2_32.dll: getaddrinfo, gethostbyname, connect)
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
        LogMsg("[Egress] Intercepted DNS getaddrinfo for '%s' -> Redirecting to '%s:%s'",
               pNodeName, g_server_ip, g_server_port);
        node = g_server_ip;
        if (pServiceName && (strcmp(pServiceName, "443") == 0 || strcmp(pServiceName, "https") == 0)) {
            service = g_server_port;
        }
    }

    return g_real_getaddrinfo(node, service, pHints, ppResult);
}

typedef struct hostent* (WSAAPI *gethostbyname_t)(const char* name);
static gethostbyname_t g_real_gethostbyname = NULL;

static struct hostent* WSAAPI Hook_gethostbyname(const char* name) {
    if (name && (strstr(name, "deadorbit.net") || strstr(name, "bungie.net"))) {
        LogMsg("[Egress] Intercepted DNS gethostbyname for '%s' -> Redirecting to '%s'",
               name, g_server_ip);
        return g_real_gethostbyname(g_server_ip);
    }
    return g_real_gethostbyname(name);
}

typedef int (WSAAPI *connect_t)(SOCKET s, const struct sockaddr* name, int namelen);
static connect_t g_real_connect = NULL;

static int WSAAPI Hook_connect(SOCKET s, const struct sockaddr* name, int namelen) {
    if (name && name->sa_family == AF_INET) {
        struct sockaddr_in* sin = (struct sockaddr_in*)name;
        uint16_t port = ntohs(sin->sin_port);
        char ip[32];
        inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));

        if (port == 443 || port == 80) {
            LogMsg("[Egress] Intercepted connect() to %s:%d -> Redirecting to %s:%s",
                   ip, port, g_server_ip, g_server_port);
            sin->sin_addr.s_addr = inet_addr(g_server_ip);
            sin->sin_port = htons((uint16_t)atoi(g_server_port));
        }
    }
    return g_real_connect(s, name, namelen);
}

static void InstallIATHooks() {
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

    g_real_getaddrinfo = (getaddrinfo_t)GetProcAddress(hWs2, "getaddrinfo");
    g_real_gethostbyname = (gethostbyname_t)GetProcAddress(hWs2, "gethostbyname");
    g_real_connect = (connect_t)GetProcAddress(hWs2, "connect");

    while (pImport->Name) {
        const char* modName = (const char*)((uint8_t*)hExe + pImport->Name);
        if (_stricmp(modName, "WS2_32.dll") == 0) {
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((uint8_t*)hExe + pImport->FirstThunk);
            while (thunk->u1.Function) {
                void* fn = (void*)thunk->u1.Function;
                void* hook = NULL;
                const char* hookName = NULL;

                if (fn == (void*)g_real_getaddrinfo) {
                    hook = (void*)Hook_getaddrinfo;
                    hookName = "getaddrinfo";
                } else if (fn == (void*)g_real_gethostbyname) {
                    hook = (void*)Hook_gethostbyname;
                    hookName = "gethostbyname";
                } else if (fn == (void*)g_real_connect) {
                    hook = (void*)Hook_connect;
                    hookName = "connect";
                }

                if (hook) {
                    DWORD oldProtect;
                    if (VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProtect)) {
                        thunk->u1.Function = (uintptr_t)hook;
                        VirtualProtect(&thunk->u1.Function, sizeof(void*), oldProtect, &oldProtect);
                        LogMsg("[Egress] Installed IAT hook for WS2_32!%s", hookName);
                    }
                }
                thunk++;
            }
            break;
        }
        pImport++;
    }
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
        AddVectoredExceptionHandler(1, VectoredCrashHandler);
        LogMsg("==================================================");
        LogMsg(" Marathon Standalone Client Proxy (Project Dawn)  ");
        LogMsg(" Target Build: 26136895 (Cryo Archive Vault Breaker)");
        LogMsg("==================================================");
        LoadConfig();
        InitInterfaceTables();
        InstallIATHooks();
    }
    return TRUE;
}
