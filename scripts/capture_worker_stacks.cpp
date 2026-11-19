// Windows PSS contexts and DbgHelp remote stack unwinding. No target writes.
#include <Windows.h>
#include <ProcessSnapshot.h>
#include <DbgHelp.h>
#include <cstdio>
#include <cstdlib>
#pragma comment(lib, "dbghelp.lib")
int main(int argc, char** argv) {
    if (argc != 2) return 2;
    DWORD pid = strtoul(argv[1], nullptr, 10);
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!process) return fprintf(stderr,"OpenProcess %lu\n",GetLastError()),1;
    SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_NO_PROMPTS | SYMOPT_IGNORE_NT_SYMPATH);
    if (!SymInitialize(process,"D:\\Marathon-preservation\\analysis",TRUE)) {
        CloseHandle(process); return fprintf(stderr,"SymInitialize %lu\n",GetLastError()),1;
    }
    HPSS snapshot{}; HPSSWALK marker{};
    DWORD error = PssCaptureSnapshot(process,PSS_CAPTURE_THREADS | PSS_CAPTURE_THREAD_CONTEXT,CONTEXT_FULL,&snapshot);
    if (error) { SymCleanup(process); CloseHandle(process); return fprintf(stderr,"PSS %lu\n",error),1; }
    error=PssWalkMarkerCreate(nullptr,&marker);
    if (!error) {
        PSS_THREAD_ENTRY entry{};
        while (!(error=PssWalkSnapshot(snapshot,PSS_WALK_THREADS,marker,&entry,sizeof(entry)))) {
            if (!entry.ContextRecord) continue;
            CONTEXT context=*entry.ContextRecord;
            STACKFRAME64 frame{};
            frame.AddrPC.Offset=context.Rip; frame.AddrPC.Mode=AddrModeFlat;
            frame.AddrStack.Offset=context.Rsp; frame.AddrStack.Mode=AddrModeFlat;
            frame.AddrFrame.Offset=context.Rbp; frame.AddrFrame.Mode=AddrModeFlat;
            HANDLE thread=OpenThread(THREAD_QUERY_LIMITED_INFORMATION,FALSE,entry.ThreadId);
            PWSTR description=nullptr;
            if(thread) GetThreadDescription(thread,&description);
            printf("THREAD %lu name=%ls rip=%llx rsp=%llx\n",entry.ThreadId,
                   description?description:L"",context.Rip,context.Rsp);
            if(description) LocalFree(description);
            if(thread) CloseHandle(thread);
            for (int n=0;n<48;n++) {
                if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64,process,nullptr,&frame,&context,nullptr,
                                 SymFunctionTableAccess64,SymGetModuleBase64,nullptr)) break;
                DWORD64 base=SymGetModuleBase64(process,frame.AddrPC.Offset);
                if (!base) { printf("  STOP: unmapped PC; protected unwind unsupported\n"); break; }
                IMAGEHLP_MODULE64 mod{}; mod.SizeOfStruct=sizeof(mod);
                SymGetModuleInfo64(process,frame.AddrPC.Offset,&mod);
                printf("  %s+%llx pc=%llx sp=%llx rcx=%llx rdx=%llx rbx=%llx rsi=%llx rdi=%llx\n",
                    mod.ModuleName,frame.AddrPC.Offset-base,frame.AddrPC.Offset,frame.AddrStack.Offset,
                    context.Rcx,context.Rdx,context.Rbx,context.Rsi,context.Rdi);
                if (!frame.AddrReturn.Offset) break;
            }
        }
        PssWalkMarkerFree(marker);
    }
    DWORD cleanup=PssFreeSnapshot(GetCurrentProcess(),snapshot);
    SymCleanup(process); CloseHandle(process);
    if (error!=ERROR_NO_MORE_ITEMS || cleanup) return fprintf(stderr,"walk=%lu cleanup=%lu\n",error,cleanup),1;
    return 0;
}
