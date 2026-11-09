import os

filepath = r'D:\vault-breaker-preservation\client_proxy\steam_api64.cpp'
with open(filepath, 'r', encoding='utf-8') as f:
    code = f.read()

# 1. Remove Hook_GetProcAddress from K32 hook in HookModuleIAT
old_k32 = '''                } else if (isK32) {
                    if (!(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                        PIMAGE_IMPORT_BY_NAME impName = (PIMAGE_IMPORT_BY_NAME)((uint8_t*)hMod + origThunk->u1.AddressOfData);
                        const char* name = (const char*)impName->Name;
                        if (strcmp(name, "CreateFileW") == 0) { hook = (void*)Hook_CreateFileW; hookName = "CreateFileW"; }
                        else if (strcmp(name, "CreateFileA") == 0) { hook = (void*)Hook_CreateFileA; hookName = "CreateFileA"; }
                        else if (strcmp(name, "GetProcAddress") == 0) { hook = (void*)Hook_GetProcAddress; hookName = "GetProcAddress"; }
                    }
                }'''

new_k32 = '''                } else if (isK32) {
                    if (!(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                        PIMAGE_IMPORT_BY_NAME impName = (PIMAGE_IMPORT_BY_NAME)((uint8_t*)hMod + origThunk->u1.AddressOfData);
                        const char* name = (const char*)impName->Name;
                        if (strcmp(name, "CreateFileW") == 0) { hook = (void*)Hook_CreateFileW; hookName = "CreateFileW"; }
                        else if (strcmp(name, "CreateFileA") == 0) { hook = (void*)Hook_CreateFileA; hookName = "CreateFileA"; }
                    }
                }'''

if old_k32 in code:
    code = code.replace(old_k32, new_k32)

# 2. Revert CheckDynamicModules to safe GetModuleHandleA
old_dyn = '''static void CheckDynamicModules() {
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

new_dyn = '''static bool g_partywin_hooked = false;
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

if old_dyn in code:
    code = code.replace(old_dyn, new_dyn)

with open(filepath, 'w', encoding='utf-8') as f:
    f.write(code)
print('Restored safe module loading and disabled GetProcAddress hook!')
