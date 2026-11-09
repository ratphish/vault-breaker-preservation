import subprocess

code = r"""#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

HANDLE g_event = NULL;

void DeepFunction3() {
    WaitForSingleObject(g_event, INFINITE);
}
void DeepFunction2() {
    DeepFunction3();
}
void DeepFunction1() {
    DeepFunction2();
}
DWORD WINAPI Worker1(LPVOID lpParam) {
    DeepFunction1();
    return 0;
}

static bool FormatAddr(void* addr, char* buf, size_t bufSize) {
    if (!addr) return false;
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
    return false;
}

void DumpThreadCallstack(HANDLE hThread, DWORD tid) {
    SuspendThread(hThread);
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (GetThreadContext(hThread, &ctx)) {
        char ripStr[128] = "Unknown";
        FormatAddr((void*)ctx.Rip, ripStr, sizeof(ripStr));
        printf("TID %u RIP: %s\n", tid, ripStr);

        // Scan stack memory (up to 128 pointers) for valid module addresses
        DWORD64* stack = (DWORD64*)ctx.Rsp;
        int frames = 0;
        printf("  Callstack scan:\n");
        for (int i = 0; i < 128 && frames < 8; i++) {
            DWORD64 val = stack[i];
            char sym[128];
            if (FormatAddr((void*)val, sym, sizeof(sym))) {
                // Avoid logging immediate RIP duplicate
                printf("    [%2d] RSP+%03X: %s\n", frames++, i*8, sym);
            }
        }
    }
    ResumeThread(hThread);
}

int main() {
    g_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    HANDLE h1 = CreateThread(NULL, 0, Worker1, NULL, 0, NULL);
    Sleep(100);

    DumpThreadCallstack(h1, GetThreadId(h1));

    SetEvent(g_event);
    WaitForSingleObject(h1, 1000);
    CloseHandle(h1);
    CloseHandle(g_event);
    return 0;
}
"""

with open(r'd:\vault-breaker-preservation\scratch\test_thread_snapshot.cpp', 'w') as f:
    f.write(code)

res = subprocess.run(r'cmd.exe /c d:\vault-breaker-preservation\scratch\run.bat', capture_output=True, text=True)
print("STDOUT:\n", res.stdout)
print("STDERR:\n", res.stderr)
