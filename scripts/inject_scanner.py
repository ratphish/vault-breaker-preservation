scanner_code = '''
static DWORD WINAPI ScanMemoryForSignonErrorThread(LPVOID lpParam) {
    Sleep(300);
    HMODULE hExe = GetModuleHandle(NULL);
    if (!hExe) return 0;
    
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hExe;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hExe + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    
    DWORD imageSize = nt->OptionalHeader.SizeOfImage;
    BYTE* base = (BYTE*)hExe;
    LogMsg("[MemScan] Starting Marathon.exe memory scan (base=%p, size=0x%X)...", base, imageSize);
    
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* cur = base;
    BYTE* end = base + imageSize;
    
    uint32_t target_hash = 88915786;
    const char* str_signon_err = "error.signon_error";
    size_t len_signon_err = strlen(str_signon_err);
    const char* str_signon = "/SignOn";
    size_t len_signon = strlen(str_signon);
    const char* str_kto = "state_change_reason_hash";
    size_t len_kto = strlen(str_kto);
    
    while (cur < end && VirtualQuery(cur, &mbi, sizeof(mbi))) {
        if ((mbi.State == MEM_COMMIT) && !(mbi.Protect & PAGE_GUARD) && 
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
            
            BYTE* page_start = (BYTE*)mbi.BaseAddress;
            SIZE_T page_len = mbi.RegionSize;
            if (page_start + page_len > end) page_len = end - page_start;
            
            // 1. Search for hash 88915786
            if (page_len >= 4) {
                for (SIZE_T i = 0; i <= page_len - 4; i += 4) {
                    if (*(uint32_t*)(page_start + i) == target_hash) {
                        DWORD rva = (DWORD)((page_start + i) - base);
                        LogMsg("[MemScan] Found hash 88915786 at Marathon.exe+0x%X (VA=%p)", rva, page_start + i);
                        char fn[MAX_PATH];
                        snprintf(fn, sizeof(fn), "D:\\Marathon-live\\mem_hash_%X.bin", rva);
                        FILE* fp = fopen(fn, "wb");
                        if (fp) {
                            BYTE* s = (page_start + i >= base + 128) ? (page_start + i - 128) : page_start;
                            fwrite(s, 1, 256, fp);
                            fclose(fp);
                            LogMsg("[MemScan] Dumped 256 bytes around hash to %s", fn);
                        }
                    }
                }
            }
            
            // 2. Search for "error.signon_error"
            if (page_len >= len_signon_err) {
                for (SIZE_T i = 0; i <= page_len - len_signon_err; i++) {
                    if (memcmp(page_start + i, str_signon_err, len_signon_err) == 0) {
                        DWORD rva = (DWORD)((page_start + i) - base);
                        LogMsg("[MemScan] Found string 'error.signon_error' at Marathon.exe+0x%X (VA=%p)", rva, page_start + i);
                    }
                }
            }
            
            // 3. Search for "/SignOn"
            if (page_len >= len_signon) {
                for (SIZE_T i = 0; i <= page_len - len_signon; i++) {
                    if (memcmp(page_start + i, str_signon, len_signon) == 0 && (page_start + i + len_signon)[0] <= ' ') {
                        DWORD rva = (DWORD)((page_start + i) - base);
                        LogMsg("[MemScan] Found string '/SignOn' at Marathon.exe+0x%X (VA=%p)", rva, page_start + i);
                    }
                }
            }
        }
        cur = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
    }
    
    LogMsg("[MemScan] Scan completed.");
    return 0;
}
static volatile LONG g_scan_started = 0;
'''

path = r'D:\vault-breaker-preservation\client_proxy\steam_api64_diag.cpp'
with open(path, 'r', encoding='utf-8') as f:
    text = f.read()

target = 'static CertVerifyCertificateChainPolicy_t g_real_CertVerifyCertificateChainPolicy = NULL;'
replacement = scanner_code + '\n' + target
assert target in text, "Target not found!"
text = text.replace(target, replacement, 1)

# Now inside Hook_CertVerifyCertificateChainPolicy, trigger the scan
trigger_target = 'LogCallerInfo("Crypto-Caller", caller);'
trigger_code = '''LogCallerInfo("Crypto-Caller", caller);
    if (InterlockedCompareExchange(&g_scan_started, 1, 0) == 0) {
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ScanMemoryForSignonErrorThread, NULL, 0, NULL);
    }'''
assert trigger_target in text, "Trigger target not found!"
text = text.replace(trigger_target, trigger_code, 1)

with open(path, 'w', encoding='utf-8') as f:
    f.write(text)

print("Successfully injected scanner into steam_api64_diag.cpp!")
