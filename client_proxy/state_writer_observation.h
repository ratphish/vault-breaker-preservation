#pragma once
#ifdef MARATHON_STATE_RECEIVER_TRACE
// A bounded guard on the client's own lmdetail mapping observes the real
// state publisher. No code bytes, CPU registers, or completion values change.
static uintptr_t g_detail_mapping=0;
static std::atomic<unsigned> g_detail_observations{0};
static char g_detail_directory[MAX_PATH]={};
static LONG CALLBACK ObserveDetailWriter(EXCEPTION_POINTERS* exception) {
    auto record=exception->ExceptionRecord;
    if(record->ExceptionCode!=STATUS_GUARD_PAGE_VIOLATION || record->NumberParameters<2
       || record->ExceptionInformation[1]<g_detail_mapping
       || record->ExceptionInformation[1]>=g_detail_mapping+4096)return EXCEPTION_CONTINUE_SEARCH;
    const unsigned sample=++g_detail_observations;
    if(sample<=16) {
        const DWORD error=GetLastError(); const int crtError=errno;
        auto context=exception->ContextRecord;
        LogMsg("[StateWriter] sample=%u access=%llu address=%p rip=%p rsp=%p rcx=%p rdx=%p rsi=%p rdi=%p r8=%p r9=%p",
            sample,(unsigned long long)record->ExceptionInformation[0],(void*)record->ExceptionInformation[1],
            (void*)context->Rip,(void*)context->Rsp,(void*)context->Rcx,(void*)context->Rdx,
            (void*)context->Rsi,(void*)context->Rdi,(void*)context->R8,(void*)context->R9);
        char path[MAX_PATH]={};
        snprintf(path,sizeof(path),"%s\\writer-%lu-%u.ctx",g_detail_directory,GetCurrentProcessId(),sample);
        FILE* file=fopen(path,"wb");
        if(file){fwrite(context,1,sizeof(*context),file);fclose(file);}
        unsigned char bytes[65536];SIZE_T count=0;
        const uintptr_t top=__readgsqword(8);
        const SIZE_T length=top>context->Rsp?(SIZE_T)((top-context->Rsp)<sizeof(bytes)?top-context->Rsp:sizeof(bytes)):0;
        if(length && ReadProcessMemory(GetCurrentProcess(),(void*)context->Rsp,bytes,length,&count)) {
            snprintf(path,sizeof(path),"%s\\writer-%lu-%u.stack",g_detail_directory,GetCurrentProcessId(),sample);
            file=fopen(path,"wb");if(file){fwrite(bytes,1,count,file);fclose(file);}
        }
        count=0;
        if(ReadProcessMemory(GetCurrentProcess(),(void*)(context->Rip-128),bytes,512,&count)) {
            snprintf(path,sizeof(path),"%s\\writer-%lu-%u.code",g_detail_directory,GetCurrentProcessId(),sample);
            file=fopen(path,"wb");if(file){fwrite(bytes,1,count,file);fclose(file);}
        }
        errno=crtError;SetLastError(error);
    }
    // Windows already cleared PAGE_GUARD. Resume the faulting instruction.
    return EXCEPTION_CONTINUE_EXECUTION;
}

static void InstallStateWriterObservation() {
    static ULONGLONG previous=0;
    const auto now=GetTickCount64();
    if(now-previous<1000 || g_detail_observations>=16)return;
    previous=now;
    DWORD count=GetEnvironmentVariableA("MARATHON_RECEIVER_CAPTURE_DIR",g_detail_directory,MAX_PATH);
    if(!count || count>=MAX_PATH)return;
    char arm[MAX_PATH]={};snprintf(arm,sizeof(arm),"%s\\ARM_WRITER_GUARD",g_detail_directory);
    if(GetFileAttributesA(arm)==INVALID_FILE_ATTRIBUTES)return;
    if(!g_detail_mapping) {
        MEMORY_BASIC_INFORMATION info{};uintptr_t address=0;
        auto module=GetModuleHandleA("kernel32.dll");
        using MappedName=DWORD(WINAPI*)(HANDLE,LPVOID,LPWSTR,DWORD);
        auto mappedName=(MappedName)::GetProcAddress(module,"K32GetMappedFileNameW");
        if(!mappedName)return;
        while(VirtualQuery((void*)address,&info,sizeof(info))) {
            if(info.State==MEM_COMMIT && info.Type==MEM_MAPPED && info.Protect==PAGE_READWRITE) {
                wchar_t name[1024]={};
                if(mappedName(GetCurrentProcess(),info.BaseAddress,name,1024) && wcsstr(name,L"\\Marathon\\lmdetail.json")) {
                    if(!AddVectoredExceptionHandler(1,ObserveDetailWriter))return;
                    g_detail_mapping=(uintptr_t)info.BaseAddress;
                    LogMsg("[StateWriter] mapped=%p bytes=%llu",info.BaseAddress,(unsigned long long)info.RegionSize);
                    break;
                }
            }
            const uintptr_t next=(uintptr_t)info.BaseAddress+info.RegionSize;
            if(next<=address)break;address=next;
        }
    }
    if(g_detail_mapping) {
        DWORD old=0;VirtualProtect((void*)g_detail_mapping,4096,PAGE_READWRITE|PAGE_GUARD,&old);
    }
}
#else
static void InstallStateWriterObservation() {}
#endif
