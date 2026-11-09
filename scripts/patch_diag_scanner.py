import re

path = r'D:\vault-breaker-preservation\client_proxy\steam_api64_diag.cpp'

# First restore from steam_api64_baseline_14D83586.cpp or clean up
# Let's see if we have steam_api64_baseline_14D83586.cpp
baseline_path = r'D:\vault-breaker-preservation\client_proxy\steam_api64_baseline_14D83586.cpp'
with open(baseline_path, 'r', encoding='utf-8') as f:
    content = f.read()

# Replace the entire ScanMemoryForSignonErrorThread function (or add it if not in baseline)
# Let's check if ScanMemoryForSignonErrorThread is in baseline
has_scan = 'ScanMemoryForSignonErrorThread' in content

scan_code = """
static DWORD WINAPI ScanMemoryForSignonErrorThread(LPVOID lpParam) {
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
    
    // Dump Error Table around Marathon.exe+0x3683DA78
    __try {
        BYTE* errTableBase = base + 0x3683DA78;
        for (int idx = -8; idx <= 24; idx++) {
            BYTE* entry = errTableBase + (idx * 16);
            uint64_t hash = *(uint64_t*)entry;
            const char* strPtr = *(const char**)(entry + 8);
            char strBuf[64] = "<invalid>";
            __try {
                if (strPtr && (BYTE*)strPtr >= base && (BYTE*)strPtr < base + imageSize) {
                    strncpy(strBuf, strPtr, sizeof(strBuf) - 1);
                    strBuf[sizeof(strBuf) - 1] = '\\0';
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                snprintf(strBuf, sizeof(strBuf), "<fault>");
            }
            LogMsg("[ErrorTable] Entry %+2d (RVA 0x%X): hash=0x%08llX (%llu) -> '%s' (at %p)",
                   idx, (DWORD)(entry - base), (unsigned long long)hash, (unsigned long long)hash, strBuf, strPtr);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        LogMsg("[ErrorTable] Exception dumping error table");
    }

    MEMORY_BASIC_INFORMATION mbi;
    BYTE* cur = base;
    BYTE* end = base + imageSize;
    
    uint32_t target_hash = 0x054CBF4A;  // 88915786 (SQUIRREL / error.signon_error)
    uint32_t target_hash2 = 0xBF6C2503;
    int code_matches = 0;

    while (cur < end && VirtualQuery(cur, &mbi, sizeof(mbi))) {
        if ((mbi.State == MEM_COMMIT) && !(mbi.Protect & PAGE_GUARD) && 
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
            
            BYTE* page_start = (BYTE*)mbi.BaseAddress;
            SIZE_T page_len = mbi.RegionSize;
            if (page_start + page_len > end) page_len = end - page_start;
            
            bool is_exec = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

            // 1. Search for hash 0x054CBF4A / 0xBF6C2503 byte-by-byte (i++)
            if (page_len >= 4) {
                for (SIZE_T i = 0; i <= page_len - 4; i++) {
                    uint32_t val = *(uint32_t*)(page_start + i);
                    if (val == target_hash || val == target_hash2) {
                        DWORD rva = (DWORD)((page_start + i) - base);
                        LogMsg("[MemScan] Found hash 0x%08X at Marathon.exe+0x%X (VA=%p, is_exec=%d, prot=0x%X)",
                               val, rva, page_start + i, is_exec ? 1 : 0, mbi.Protect);
                        
                        char fn[MAX_PATH];
                        if (is_exec) {
                            snprintf(fn, sizeof(fn), "D:/Marathon-live/code_signon_error_%X.bin", rva);
                            FILE* fp = fopen(fn, "wb");
                            if (fp) {
                                BYTE* s = (page_start + i >= base + 256) ? (page_start + i - 256) : page_start;
                                fwrite(s, 1, 512, fp);
                                fclose(fp);
                                LogMsg("[MemScan] Dumped 512 bytes executable code around match to %s", fn);
                                code_matches++;
                            }
                        } else {
                            snprintf(fn, sizeof(fn), "D:/Marathon-live/mem_hash_%X.bin", rva);
                            FILE* fp = fopen(fn, "wb");
                            if (fp) {
                                BYTE* s = (page_start + i >= base + 128) ? (page_start + i - 128) : page_start;
                                fwrite(s, 1, 256, fp);
                                fclose(fp);
                                LogMsg("[MemScan] Dumped 256 bytes data around match to %s", fn);
                            }
                        }
                    }
                }
            }
        }
        cur = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
    }
    
    LogMsg("[MemScan] Scan completed. Found %d executable code sites.", code_matches);
    return 0;
}
static volatile LONG g_scan_started = 0;
"""

hook_cert_target = "static BOOL WINAPI Hook_CertVerifyCertificateChainPolicy("
idx = content.find(hook_cert_target)
if idx != -1:
    content = content[:idx] + scan_code + "\n" + content[idx:]

# In Hook_CertVerifyCertificateChainPolicy, trigger scan and dump TLS caller
hook_body_target = '    void* caller = _ReturnAddress();\n    char certSubject[256] = "none";'
hook_body_replacement = """    void* caller = _ReturnAddress();
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
    char certSubject[256] = "none";"""

content = content.replace(hook_body_target, hook_body_replacement, 1)

# In GetEncryptedAppTicket, dump caller around ReturnAddress
appticket_target = '    LogMsg("[SteamUser] GetEncryptedAppTicket called (pTicket=%p, max=%d, pcbTicket=%p)", pTicket, cbMaxTicket, pcbTicket);'
appticket_replacement = """    LogMsg("[SteamUser] GetEncryptedAppTicket called (pTicket=%p, max=%d, pcbTicket=%p)", pTicket, cbMaxTicket, pcbTicket);
    FILE* fpCaller = fopen("D:/Marathon-live/mem_ticket_caller.bin", "wb");
    if (fpCaller) {
        BYTE* s = ((uintptr_t)caller >= 64) ? ((BYTE*)caller - 64) : (BYTE*)caller;
        fwrite(s, 1, 256, fpCaller);
        fclose(fpCaller);
        LogMsg("[SteamUser] Dumped 256 bytes around caller (%p) to mem_ticket_caller.bin", caller);
    }"""
content = content.replace(appticket_target, appticket_replacement, 1)

with open(path, 'w', encoding='utf-8') as f:
    f.write(content)

print(f"Patched {path} from baseline successfully!")
