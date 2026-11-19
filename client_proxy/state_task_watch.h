#pragma once
#ifdef MARATHON_PROVIDER_STATE_WATCH
#include "provider_state_watch.h"
static void InstallStateTaskWatch() { provider_watch::Install(); }
#elif defined(MARATHON_STATE_TASK_WATCH)
#include <tlhelp32.h>
// Observe writes to the verified phase-8 task's status/result, without changing
// either value. A helper briefly suspends only the initiating native thread to
// install one unused hardware watchpoint; the VEH handles only that watchpoint.
struct TaskWatchThread { DWORD tid=0; DWORD64 oldDr0=0,oldDr7=0;std::atomic<bool> active{false}; };
static TaskWatchThread g_task_watch_threads[128];
static uintptr_t g_task_watch_address=0;
static std::atomic<unsigned> g_task_write_count{0};
static char g_task_watch_directory[MAX_PATH]={};
static LONG CALLBACK ObserveStateTaskWrite(EXCEPTION_POINTERS* exception) {
    auto context=exception->ContextRecord;
    if(exception->ExceptionRecord->ExceptionCode!=EXCEPTION_SINGLE_STEP
       || !(context->Dr6&1) || context->Dr0!=g_task_watch_address)return EXCEPTION_CONTINUE_SEARCH;
    TaskWatchThread* watched=nullptr;const DWORD tid=GetCurrentThreadId();
    for(auto& row:g_task_watch_threads)if(row.active.load(std::memory_order_acquire)&&row.tid==tid){watched=&row;break;}
    if(!watched)return EXCEPTION_CONTINUE_SEARCH;
    context->Dr6&=~1ull;
    const DWORD error=GetLastError();const int crtError=errno;
    const uintptr_t base=(uintptr_t)GetModuleHandleA(nullptr);
    uintptr_t vtable=0;SIZE_T got=0;
    ReadProcessMemory(GetCurrentProcess(),(void*)(base+0x3683e968),&vtable,sizeof(vtable),&got);
    if(vtable==base+0x32da9f28) {
        const unsigned sample=++g_task_write_count;
        DWORD result[2]={};ReadProcessMemory(GetCurrentProcess(),(void*)g_task_watch_address,result,sizeof(result),&got);
        LogMsg("[StateTaskWrite] sample=%u receiver=%p result=%p state=%lu result_code=%ld rip=%p rcx=%p rdx=%p r8=%p r9=%p rsp=%p",
            sample,(void*)(base+0x3683e998),(void*)(g_task_watch_address+4),result[0],(LONG)result[1],
            (void*)context->Rip,(void*)context->Rcx,(void*)context->Rdx,(void*)context->R8,(void*)context->R9,(void*)context->Rsp);
        if(sample<=16) {
            char path[MAX_PATH]={};snprintf(path,sizeof(path),"%s\\task-%lu-%u.ctx",g_task_watch_directory,GetCurrentProcessId(),sample);
            FILE* file=fopen(path,"wb");if(file){fwrite(context,1,sizeof(*context),file);fclose(file);}
            unsigned char data[65536];SIZE_T count=0;
            uintptr_t top=__readgsqword(8);SIZE_T size=top>context->Rsp?(SIZE_T)((top-context->Rsp)<sizeof(data)?top-context->Rsp:sizeof(data)):0;
            if(size && ReadProcessMemory(GetCurrentProcess(),(void*)context->Rsp,data,size,&count)) {
                snprintf(path,sizeof(path),"%s\\task-%lu-%u.stack",g_task_watch_directory,GetCurrentProcessId(),sample);
                file=fopen(path,"wb");if(file){fwrite(data,1,count,file);fclose(file);}
            }
            if(ReadProcessMemory(GetCurrentProcess(),(void*)(context->Rip-128),data,512,&count)) {
                snprintf(path,sizeof(path),"%s\\task-%lu-%u.code",g_task_watch_directory,GetCurrentProcessId(),sample);
                file=fopen(path,"wb");if(file){fwrite(data,1,count,file);fclose(file);}
            }
        }
        if(sample>=16) {
            context->Dr0=watched->oldDr0;
            context->Dr7=(context->Dr7&~0xf0003ull)|(watched->oldDr7&0xf0003ull);
            watched->active.store(false,std::memory_order_release);
        }
    }
    errno=crtError;SetLastError(error);
    return EXCEPTION_CONTINUE_EXECUTION;
}

static DWORD WINAPI ArmStateTaskWatch(void*) {
    HANDLE snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
    if(snapshot==INVALID_HANDLE_VALUE)return 1;
    THREADENTRY32 entry{};entry.dwSize=sizeof(entry);unsigned armed=0;
    for(BOOL more=Thread32First(snapshot,&entry);more;more=Thread32Next(snapshot,&entry)) {
        if(entry.th32OwnerProcessID!=GetCurrentProcessId() || entry.th32ThreadID==GetCurrentThreadId() || armed>=128)continue;
        HANDLE thread=OpenThread(THREAD_SUSPEND_RESUME|THREAD_GET_CONTEXT|THREAD_SET_CONTEXT,FALSE,entry.th32ThreadID);
        if(!thread)continue;
        if(SuspendThread(thread)==(DWORD)-1){CloseHandle(thread);continue;}
        CONTEXT context{};context.ContextFlags=CONTEXT_DEBUG_REGISTERS;
        bool configured=false;
        if(GetThreadContext(thread,&context) && !(context.Dr7&3)) {
            auto& row=g_task_watch_threads[armed];row.tid=entry.th32ThreadID;row.oldDr0=context.Dr0;row.oldDr7=context.Dr7;
            context.Dr0=g_task_watch_address;context.Dr7=(context.Dr7&~0xf0000ull)|0x90001ull;
            configured=SetThreadContext(thread,&context)!=FALSE;
            if(configured)row.active.store(true,std::memory_order_release);
        }
        ResumeThread(thread);CloseHandle(thread);
        if(configured)armed++;
    }
    CloseHandle(snapshot);
    LogMsg("[StateTaskWrite] armed_threads=%u slot=0 address=%p",armed,(void*)g_task_watch_address);
    return armed?0:2;
}

static void InstallStateTaskWatch() {
    static std::atomic<bool> started{false};
    if(started.load())return;
    const DWORD length=GetEnvironmentVariableA("MARATHON_RECEIVER_CAPTURE_DIR",g_task_watch_directory,MAX_PATH);
    if(!length || length>=MAX_PATH)return;
    char arm[MAX_PATH]={};snprintf(arm,sizeof(arm),"%s\\ARM_TASK_WATCH",g_task_watch_directory);
    if(GetFileAttributesA(arm)==INVALID_FILE_ATTRIBUTES)return;
    if(started.exchange(true))return;
    g_task_watch_address=(uintptr_t)GetModuleHandleA(nullptr)+0x3683e9a0;
    if(!AddVectoredExceptionHandler(1,ObserveStateTaskWrite))return;
    HANDLE helper=CreateThread(nullptr,0,ArmStateTaskWatch,nullptr,0,nullptr);
    if(helper)CloseHandle(helper);
}
#else
static void InstallStateTaskWatch() {}
#endif
