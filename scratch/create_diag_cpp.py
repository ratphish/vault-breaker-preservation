import re

with open(r'd:\vault-breaker-preservation\client_proxy\steam_api64_baseline_14D83586.cpp', 'r', encoding='utf-8') as f:
    code = f.read()

# 1. Add headers
header_insert = """#include <tlhelp32.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
"""
code = code.replace('#include <winhttp.h>', '#include <winhttp.h>\n' + header_insert)

# 2. Add FormatAddr, ComputeSHA256, and ThreadSnapshot infrastructure before SteamUser_RequestEncryptedAppTicket
diag_infra = r"""
// ---------------------------------------------------------------------------
// Forensic Post-Ticket Diagnostics & Thread Snapshot Monitor
// ---------------------------------------------------------------------------

static bool FormatAddr(void* addr, char* buf, size_t bufSize) {
    if (!addr) {
        strncpy(buf, "NULL", bufSize);
        return false;
    }
    HMODULE hMod = NULL;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)addr, &hMod) && hMod) {
        char fullPath[MAX_PATH];
        if (GetModuleFileNameA(hMod, fullPath, sizeof(fullPath))) {
            const char* slash = strrchr(fullPath, '\\');
            const char* modName = slash ? slash + 1 : fullPath;
            uintptr_t rva = (uintptr_t)addr - (uintptr_t)hMod;
            snprintf(buf, bufSize, "%s+0x%llX", modName, (unsigned long long)rva);
            return true;
        }
    }
    snprintf(buf, bufSize, "%p", addr);
    return false;
}

static void ComputeSHA256(const void* data, size_t len, char* hexOut) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    UCHAR hash[32];
    memset(hash, 0, sizeof(hash));
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

typedef NTSTATUS (NTAPI *NtQueryInformationThread_t)(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
);

static volatile bool g_diag_monitor_started = false;

static void CaptureThreadSnapshot(const char* label) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    NtQueryInformationThread_t pNtQuery = 
        hNtdll ? (NtQueryInformationThread_t)GetProcAddress(hNtdll, "NtQueryInformationThread") : NULL;

    DWORD myPid = GetCurrentProcessId();
    DWORD myTid = GetCurrentThreadId();

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    LogMsg("================================================================================");
    LogMsg("[THREAD-SNAPSHOT %s] PID %u active thread state audit:", label, myPid);

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == myPid && te.th32ThreadID != myTid) {
                DWORD tid = te.th32ThreadID;
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tid);
                if (hThread) {
                    void* startAddr = NULL;
                    if (pNtQuery) {
                        pNtQuery(hThread, 9 /* ThreadQuerySetWin32StartAddress */, &startAddr, sizeof(startAddr), NULL);
                    }
                    ULONG64 cycles = 0;
                    QueryThreadCycleTime(hThread, &cycles);

                    char startStr[128];
                    FormatAddr(startAddr, startStr, sizeof(startStr));

                    DWORD prev = SuspendThread(hThread);
                    CONTEXT ctx;
                    memset(&ctx, 0, sizeof(ctx));
                    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
                    char ripStr[128] = "Unknown";
                    char stackFrames[512] = "";
                    if (GetThreadContext(hThread, &ctx)) {
                        FormatAddr((void*)ctx.Rip, ripStr, sizeof(ripStr));

                        // Safe callstack memory scan using __try / __except
                        __try {
                            DWORD64* stack = (DWORD64*)ctx.Rsp;
                            int frames = 0;
                            for (int i = 0; i < 96 && frames < 5; i++) {
                                DWORD64 val = stack[i];
                                char sym[128];
                                if (FormatAddr((void*)val, sym, sizeof(sym))) {
                                    char temp[160];
                                    snprintf(temp, sizeof(temp), " -> [%s]", sym);
                                    if (strlen(stackFrames) + strlen(temp) < sizeof(stackFrames) - 1) {
                                        strcat(stackFrames, temp);
                                    }
                                    frames++;
                                }
                            }
                        } __except (EXCEPTION_EXECUTE_HANDLER) {
                            strcat(stackFrames, " -> [MemoryReadException]");
                        }
                    }
                    ResumeThread(hThread);
                    CloseHandle(hThread);

                    LogMsg("  [TID %5u] Start: %-32s | Cycles: %12llu | RIP: %-32s | Stack:%s",
                           tid, startStr, (unsigned long long)cycles, ripStr, stackFrames[0] ? stackFrames : " [NoModuleFrames]");
                }
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
    LogMsg("================================================================================");
}

static DWORD WINAPI DiagnosticSnapshotThreadProc(LPVOID lpParam) {
    LogMsg("[DiagMonitor] Snapshot monitor thread active (TID:%u). Scheduling checkpoints...", GetCurrentThreadId());
    
    // Checkpoint 1: T+0.5s (immediately after ticket delivery & cert check)
    Sleep(500);
    CaptureThreadSnapshot("T+0.5s");

    // Checkpoint 2: T+2.5s (early stall)
    Sleep(2000);
    CaptureThreadSnapshot("T+2.5s");

    // Checkpoint 3: T+7.5s (early-mid stall)
    Sleep(5000);
    CaptureThreadSnapshot("T+7.5s");

    // Checkpoint 4: T+15.0s (mid stall)
    Sleep(7500);
    CaptureThreadSnapshot("T+15.0s");

    // Checkpoint 5: T+23.0s (late stall, before 25s timeout)
    Sleep(8000);
    CaptureThreadSnapshot("T+23.0s");

    LogMsg("[DiagMonitor] All 5 thread snapshot checkpoints complete.");
    return 0;
}
"""

# Replace the entire old SteamUser_RequestEncryptedAppTicket
old_req_ticket = """static uint64_t g_next_api_call = 1;
static uint64_t SteamUser_RequestEncryptedAppTicket(void* self, void* pDataToInclude, int cbDataToInclude) {
    void* caller = _ReturnAddress();
    LogCallerInfo("SteamUser-RequestEncryptedAppTicket", caller);
    uint64_t callId = g_next_api_call++;
    LogMsg("[SteamUser] RequestEncryptedAppTicket called (pDataToInclude=%p, cb=%d) -> handle %llu",
           pDataToInclude, cbDataToInclude, (unsigned long long)callId);
    return callId;
}"""

new_req_ticket = diag_infra + r"""
static uint64_t g_next_api_call = 1;
static uint64_t SteamUser_RequestEncryptedAppTicket(void* self, void* pDataToInclude, int cbDataToInclude) {
    void* caller = _ReturnAddress();
    DWORD tid = GetCurrentThreadId();
    uint64_t timestampMs = GetTickCount64();
    LogCallerInfo("SteamUser-RequestEncryptedAppTicket", caller);
    uint64_t callId = g_next_api_call++;

    char sha256Hex[65] = "None";
    char prevHash[65] = "None";
    bool hashChanged = false;

    if (pDataToInclude && cbDataToInclude > 0) {
        ComputeSHA256(pDataToInclude, (size_t)cbDataToInclude, sha256Hex);

        // Check previous launch hash
        FILE* fpPrev = fopen("D:\\Marathon-live\\pDataToInclude_prev_hash.txt", "r");
        if (fpPrev) {
            if (fscanf(fpPrev, "%64s", prevHash) == 1) {
                hashChanged = (strcmp(sha256Hex, prevHash) != 0);
            }
            fclose(fpPrev);
        } else {
            hashChanged = true;
        }

        // Store current hash
        FILE* fpNew = fopen("D:\\Marathon-live\\pDataToInclude_prev_hash.txt", "w");
        if (fpNew) {
            fprintf(fpNew, "%s\n", sha256Hex);
            fclose(fpNew);
        }

        // Store raw bytes in restricted local diagnostic file ONLY
        FILE* fpRaw = fopen("D:\\Marathon-live\\pDataToInclude_raw.bin", "wb");
        if (fpRaw) {
            fwrite(pDataToInclude, 1, cbDataToInclude, fpRaw);
            fclose(fpRaw);
        }
    }

    LogMsg("[SteamUser] RequestEncryptedAppTicket called: len=%d bytes, SHA-256=%s, changed_from_last_run=%s, callId=%llu, timestamp=%llu ms",
           cbDataToInclude, sha256Hex, hashChanged ? "YES" : "NO (identical to previous launch)",
           (unsigned long long)callId, (unsigned long long)timestampMs);

    // Launch thread snapshot monitor if not already running
    if (!g_diag_monitor_started) {
        g_diag_monitor_started = true;
        CreateThread(NULL, 0, DiagnosticSnapshotThreadProc, NULL, 0, NULL);
    }

    return callId;
}"""

assert old_req_ticket in code, "Could not find old_req_ticket in code"
code = code.replace(old_req_ticket, new_req_ticket)

# 3. Add vtable stub templates for other interfaces
stubs_target = """template<int N>
static int64_t UserStub(void* self, ...) {
    void* caller = _ReturnAddress();
    LogMsg("[SteamUser-STUB] Slot %d called! (self=%p, caller=%p)", N, self, caller);
    return 0;
}

#define S8(b) (void*)UserStub<b+0>, (void*)UserStub<b+1>, (void*)UserStub<b+2>, (void*)UserStub<b+3>, (void*)UserStub<b+4>, (void*)UserStub<b+5>, (void*)UserStub<b+6>, (void*)UserStub<b+7>
static void* g_user_default_stubs[64] = {
    S8(0), S8(8), S8(16), S8(24), S8(32), S8(40), S8(48), S8(56)
};"""

new_stubs = """template<int N>
static int64_t UserStub(void* self, ...) {
    void* caller = _ReturnAddress();
    LogCallerInfo("ISteamUser-STUB", caller);
    LogMsg("[VTABLE-STUB] ISteamUser Slot %d called! (self=%p, caller=%p)", N, self, caller);
    return 0;
}
#define U8(b) (void*)UserStub<b+0>, (void*)UserStub<b+1>, (void*)UserStub<b+2>, (void*)UserStub<b+3>, (void*)UserStub<b+4>, (void*)UserStub<b+5>, (void*)UserStub<b+6>, (void*)UserStub<b+7>
static void* g_user_default_stubs[64] = {
    U8(0), U8(8), U8(16), U8(24), U8(32), U8(40), U8(48), U8(56)
};

template<int N>
static int64_t AppsStub(void* self, ...) {
    void* caller = _ReturnAddress();
    LogCallerInfo("ISteamApps-STUB", caller);
    LogMsg("[VTABLE-STUB] ISteamApps Slot %d called! (self=%p, caller=%p)", N, self, caller);
    return 0;
}
#define A8(b) (void*)AppsStub<b+0>, (void*)AppsStub<b+1>, (void*)AppsStub<b+2>, (void*)AppsStub<b+3>, (void*)AppsStub<b+4>, (void*)AppsStub<b+5>, (void*)AppsStub<b+6>, (void*)AppsStub<b+7>
static void* g_apps_default_stubs[64] = {
    A8(0), A8(8), A8(16), A8(24), A8(32), A8(40), A8(48), A8(56)
};

template<int N>
static int64_t UtilsStub(void* self, ...) {
    void* caller = _ReturnAddress();
    LogCallerInfo("ISteamUtils-STUB", caller);
    LogMsg("[VTABLE-STUB] ISteamUtils Slot %d called! (self=%p, caller=%p)", N, self, caller);
    return 0;
}
#define UT8(b) (void*)UtilsStub<b+0>, (void*)UtilsStub<b+1>, (void*)UtilsStub<b+2>, (void*)UtilsStub<b+3>, (void*)UtilsStub<b+4>, (void*)UtilsStub<b+5>, (void*)UtilsStub<b+6>, (void*)UtilsStub<b+7>
static void* g_utils_default_stubs[64] = {
    UT8(0), UT8(8), UT8(16), UT8(24), UT8(32), UT8(40), UT8(48), UT8(56)
};

template<int N>
static int64_t FriendsStub(void* self, ...) {
    void* caller = _ReturnAddress();
    LogCallerInfo("ISteamFriends-STUB", caller);
    LogMsg("[VTABLE-STUB] ISteamFriends Slot %d called! (self=%p, caller=%p)", N, self, caller);
    return 0;
}
#define F8(b) (void*)FriendsStub<b+0>, (void*)FriendsStub<b+1>, (void*)FriendsStub<b+2>, (void*)FriendsStub<b+3>, (void*)FriendsStub<b+4>, (void*)FriendsStub<b+5>, (void*)FriendsStub<b+6>, (void*)FriendsStub<b+7>
static void* g_friends_default_stubs[80] = {
    F8(0), F8(8), F8(16), F8(24), F8(32), F8(40), F8(48), F8(56), F8(64), F8(72)
};
"""

assert stubs_target in code, "Could not find stubs_target in code"
code = code.replace(stubs_target, new_stubs)

# 4. In InitInterfaceTables, use the default stub arrays
init_target = """    for (int i = 0; i < 128; i++) g_generic_vtable[i] = (void*)MethodReturnZero;
    for (int i = 0; i < 64; i++) g_user_vtable[i] = g_user_default_stubs[i];
    for (int i = 0; i < 64; i++) g_utils_vtable[i] = (void*)MethodReturnZero;
    for (int i = 0; i < 64; i++) g_apps_vtable[i] = (void*)MethodReturnZero;
    for (int i = 0; i < 80; i++) g_friends_vtable[i] = (void*)MethodReturnZero;
    for (int i = 0; i < 64; i++) g_userstats_vtable[i] = (void*)MethodReturnZero;
    for (int i = 0; i < 64; i++) g_input_vtable[i] = (void*)MethodReturnZero;"""

new_init = """    for (int i = 0; i < 128; i++) g_generic_vtable[i] = (void*)MethodReturnZero;
    for (int i = 0; i < 64; i++) g_user_vtable[i] = g_user_default_stubs[i];
    for (int i = 0; i < 64; i++) g_utils_vtable[i] = g_utils_default_stubs[i];
    for (int i = 0; i < 64; i++) g_apps_vtable[i] = g_apps_default_stubs[i];
    for (int i = 0; i < 80; i++) g_friends_vtable[i] = g_friends_default_stubs[i];
    for (int i = 0; i < 64; i++) g_userstats_vtable[i] = (void*)MethodReturnZero;
    for (int i = 0; i < 64; i++) g_input_vtable[i] = (void*)MethodReturnZero;"""

assert init_target in code, "Could not find init_target in code"
code = code.replace(init_target, new_init)

# 5. In DllMain, update banner
dllmain_target = """        LogMsg("==================================================");
        LogMsg(" Marathon Standalone Client Proxy (Project Dawn)  ");
        LogMsg(" Target Build: 26136895 (Cryo Archive Vault Breaker)");
        LogMsg(" Log file active at: %s", g_log_path);
        LogMsg("==================================================");"""

new_dllmain = """        LogMsg("==================================================");
        LogMsg(" Marathon Client Proxy [DIAGNOSTIC INSTRUMENTED]  ");
        LogMsg(" Build ID: STINGRAY-POST-TICKET-TRACE-v1          ");
        LogMsg(" Control Baseline SHA-256: 14D835863464502839D9E624B9E2A26F85130508F3B0066BF859A54A8CF213C8");
        LogMsg(" Target Build: 26136895 (Cryo Archive Vault Breaker)");
        LogMsg(" Log file active at: %s", g_log_path);
        LogMsg("==================================================");"""

assert dllmain_target in code, "Could not find dllmain_target in code"
code = code.replace(dllmain_target, new_dllmain)

with open(r'd:\vault-breaker-preservation\client_proxy\steam_api64_diag.cpp', 'w', encoding='utf-8') as f:
    f.write(code)

print("Generated steam_api64_diag.cpp successfully!")
