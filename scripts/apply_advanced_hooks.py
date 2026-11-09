import os

filepath = r'D:\vault-breaker-preservation\client_proxy\steam_api64.cpp'
with open(filepath, 'r', encoding='utf-8') as f:
    code = f.read()

target = '''static bool g_partywin_hooked = false;
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

}'''

replacement = '''static HMODULE g_hooked_modules[256];
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

static void CheckDynamicModules() {
    uint8_t* pPeb = (uint8_t*)__readgsqword(0x60);
    if (!pPeb) return;
    PEB_LDR_DATA_PEB* pLdr = *(PEB_LDR_DATA_PEB**)(pPeb + 0x18);
    if (!pLdr) return;
    LIST_ENTRY* pHead = &pLdr->InLoadOrderModuleList;
    LIST_ENTRY* pCurrent = pHead->Flink;
    while (pCurrent && pCurrent != pHead) {
        LDR_DATA_TABLE_ENTRY_PEB* pEntry = CONTAINING_RECORD(pCurrent, LDR_DATA_TABLE_ENTRY_PEB, InLoadOrderLinks);
        if (pEntry && pEntry->DllBase) {
            HMODULE hMod = (HMODULE)pEntry->DllBase;
            if (!IsModuleHooked(hMod)) {
                char name[64] = "Unknown";
                if (pEntry->BaseDllName.Buffer && pEntry->BaseDllName.Length > 0) {
                    WideCharToMultiByte(CP_UTF8, 0, pEntry->BaseDllName.Buffer, pEntry->BaseDllName.Length / sizeof(WCHAR), name, sizeof(name) - 1, NULL, NULL);
                }
                HookModuleIAT(hMod, name);
                MarkModuleHooked(hMod);
            }
        }
        pCurrent = pCurrent->Flink;
    }
}'''

assert target in code, "Target CheckDynamicModules not found"
code = code.replace(target, replacement)

with open(filepath, 'w', encoding='utf-8') as f:
    f.write(code)
print('Applied PEB dynamic module hooking!')
