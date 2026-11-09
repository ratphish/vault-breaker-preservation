import re

path = r'D:\vault-breaker-preservation\client_proxy\steam_api64_diag.cpp'
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

# Let's add the bootflow table dump and RIP-relative reference scanner to ScanMemoryForSignonErrorThread
new_scan_code = """static DWORD WINAPI ScanMemoryForSignonErrorThread(LPVOID lpParam) {
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

    // 2. Scan executable code for RIP-relative references to 0x3683DA78 (error.signon_denied) and 0x3683DA68 (error.signon_error)
    DWORD target_rva1 = 0x3683DA78;
    DWORD target_rva2 = 0x3683DA68;
    int ref_count = 0;

    MEMORY_BASIC_INFORMATION mbi;
    BYTE* cur = base;
    BYTE* end = base + imageSize;

    while (cur < end && VirtualQuery(cur, &mbi, sizeof(mbi))) {
        if ((mbi.State == MEM_COMMIT) && !(mbi.Protect & PAGE_GUARD) && 
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
            
            BYTE* page_start = (BYTE*)mbi.BaseAddress;
            SIZE_T page_len = mbi.RegionSize;
            if (page_start + page_len > end) page_len = end - page_start;

            if (page_len >= 7) {
                for (SIZE_T i = 0; i <= page_len - 7; i++) {
                    BYTE b0 = page_start[i];
                    BYTE b1 = page_start[i+1];
                    // Look for LEA r64, [rip+disp32] (48 8D or 4C 8D) or MOV r64, [rip+disp32] (48 8B or 4C 8B)
                    if ((b0 == 0x48 || b0 == 0x4C) && (b1 == 0x8D || b1 == 0x8B)) {
                        int32_t disp = *(int32_t*)(page_start + i + 3);
                        DWORD instr_rva = (DWORD)((page_start + i) - base);
                        DWORD rip_after = instr_rva + 7;
                        DWORD target = rip_after + disp;

                        if (target == target_rva1 || target == target_rva2) {
                            LogMsg("[MemScan] Found ref to error entry 0x%X at Marathon.exe+0x%X (VA=%p, op=%02X %02X, disp=0x%X)",
                                   target, instr_rva, page_start + i, b0, b1, disp);
                            char fn[MAX_PATH];
                            snprintf(fn, sizeof(fn), "D:/Marathon-live/code_error_ref_%X.bin", instr_rva);
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
        }
        cur = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
    }
    LogMsg("[MemScan] Scan completed. Found %d references to signon error table.", ref_count);
    return 0;
}"""

old_pattern = re.compile(
    r'static DWORD WINAPI ScanMemoryForSignonErrorThread\(LPVOID lpParam\) \{.*?LogMsg\("\[MemScan\] Scan completed\..*?"\s*,\s*code_matches\);\s*return 0;\s*\}',
    re.DOTALL
)

match = old_pattern.search(content)
if not match:
    print("ERROR: old_pattern did not match!")
    # Let's search simpler
    idx1 = content.find("static DWORD WINAPI ScanMemoryForSignonErrorThread(")
    idx2 = content.find("static volatile LONG g_scan_started = 0;")
    if idx1 != -1 and idx2 != -1:
        content = content[:idx1] + new_scan_code + "\n" + content[idx2:]
        print("Replaced via index markers!")
    else:
        print("ERROR: could not find scan thread markers!")
        exit(1)
else:
    content = content[:match.start()] + new_scan_code + content[match.end():]
    print("Replaced via regex!")

with open(path, 'w', encoding='utf-8') as f:
    f.write(content)

print(f"Updated {path} successfully!")
