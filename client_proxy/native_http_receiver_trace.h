#pragma once
#include <stdio.h>
#include <intrin.h>
// Opt-in diagnostic: preserve every argument and tail-call the native method.
// This observes actual virtual-call receivers; it never invents result layouts.
#ifdef MARATHON_NATIVE_RECEIVER_TRACE
static void* g_http_original_methods[32] = {};
static void* g_http_trace_vtable[33] = {};
static std::atomic<unsigned long> g_http_receiver_counts[128];

static void __fastcall TraceNativeHttpReceiver(unsigned slot, const uintptr_t* saved) {
    const DWORD error=GetLastError(); const int crtError=errno;
    const unsigned long n=++g_http_receiver_counts[slot];
    if (n<=32 || (n & 4095)==0) {
        // Stack: r15,r14,r13,r12,rdi,rsi,rbp,rbx,r11,r10,r9,r8,rdx,rcx,rax,flags,return.
        LogMsg("[NativeReceiver] slot=%u sample=%lu receiver=%p rdx=%p r8=%p r9=%p caller=%p rsp=%p",
            slot,n,(void*)saved[13],(void*)saved[12],(void*)saved[11],(void*)saved[10],
            (void*)saved[16],(void*)(saved+16));
        if(n<=4) {
            LogMsg("[NativeReceiverRegs] slot=%u rbx=%p rbp=%p rsi=%p rdi=%p r12=%p r13=%p r14=%p r15=%p",
                slot,(void*)saved[7],(void*)saved[6],(void*)saved[5],(void*)saved[4],
                (void*)saved[3],(void*)saved[2],(void*)saved[1],(void*)saved[0]);
            char directory[MAX_PATH]={},path[MAX_PATH]={};
            DWORD length=GetEnvironmentVariableA("MARATHON_RECEIVER_CAPTURE_DIR",directory,MAX_PATH);
            if(length && length<MAX_PATH && snprintf(path,sizeof(path),"%s\\%lu-%lu-slot%u-%lu.bin",
                directory,GetCurrentProcessId(),GetCurrentThreadId(),slot,n)>0) {
                FILE* file=fopen(path,"wb");
                if(file) {
                    fwrite(saved,sizeof(uintptr_t),17,file);
                    unsigned char stack[16384];SIZE_T bytes=0;
                    const uintptr_t top=__readgsqword(8),start=(uintptr_t)(saved+16);
                    const SIZE_T count=top>start ? (SIZE_T)((top-start)<sizeof(stack)?top-start:sizeof(stack)):0;
                    if(count)ReadProcessMemory(GetCurrentProcess(),saved+16,stack,count,&bytes);
                    if(bytes)fwrite(stack,1,bytes,file);
                    fclose(file);
                }
                // Preserve metadata around the actual URL argument before its caller's stack is reused.
                if(slot==6 && saved[12]>=0x10080) {
                    char argumentPath[MAX_PATH]={};
                    snprintf(argumentPath,sizeof(argumentPath),"%s\\%lu-%lu-slot%u-%lu.arg.bin",
                        directory,GetCurrentProcessId(),GetCurrentThreadId(),slot,n);
                    unsigned char arguments[1152];SIZE_T bytes=0;
                    if(ReadProcessMemory(GetCurrentProcess(),(void*)(saved[12]-128),arguments,sizeof(arguments),&bytes)) {
                        FILE* argumentFile=fopen(argumentPath,"wb");
                        if(argumentFile){fwrite(arguments,1,bytes,argumentFile);fclose(argumentFile);}
                    }
                }
            }
        }
    }
    errno=crtError; SetLastError(error);
}

static void* MakeNativeHttpObserver(unsigned slot, void* original) {
    unsigned char code[256]; size_t used=0;
    auto emit=[&](unsigned char b){code[used++]=b;};
    auto imm64=[&](uintptr_t v){memcpy(code+used,&v,8);used+=8;};
    // Save flags, all volatile GPRs and all volatile vector registers.
    const unsigned char pushes[]={0x9c,0x50,0x51,0x52,0x41,0x50,0x41,0x51,0x41,0x52,0x41,0x53,
        0x53,0x55,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,
        0x48,0x81,0xec,0x88,0,0,0};
    for(auto b:pushes)emit(b);
    for(unsigned r=0;r<6;r++) { emit(0xf3);emit(0x0f);emit(0x7f);emit(0x44+r*8);emit(0x24);emit(0x20+r*16); }
    emit(0xb9); unsigned value=slot;memcpy(code+used,&value,4);used+=4;
    const unsigned char frame[]={0x48,0x8d,0x94,0x24,0x88,0,0,0};
    for(auto b:frame)emit(b);
    emit(0x48);emit(0xb8);imm64((uintptr_t)&TraceNativeHttpReceiver);emit(0xff);emit(0xd0);
    for(unsigned r=0;r<6;r++) { emit(0xf3);emit(0x0f);emit(0x6f);emit(0x44+r*8);emit(0x24);emit(0x20+r*16); }
    const unsigned char pops[]={0x48,0x81,0xc4,0x88,0,0,0,
        0x41,0x5f,0x41,0x5e,0x41,0x5d,0x41,0x5c,0x5f,0x5e,0x5d,0x5b,
        0x41,0x5b,0x41,0x5a,0x41,0x59,
        0x41,0x58,0x5a,0x59,0x58,0x9d,0xff,0x25,0,0,0,0};
    for(auto b:pops)emit(b);
    imm64((uintptr_t)original);
    void* memory=VirtualAlloc(nullptr,4096,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if(!memory)return nullptr;
    memcpy(memory,code,used);DWORD old;
    if(!VirtualProtect(memory,4096,PAGE_EXECUTE_READ,&old)) {VirtualFree(memory,0,MEM_RELEASE);return nullptr;}
    FlushInstructionCache(GetCurrentProcess(),memory,used);
    return memory;
}

static void InstallNativeHttpReceiverTrace() {
    static SRWLOCK lock=SRWLOCK_INIT;
    if(!TryAcquireSRWLockExclusive(&lock))return;
    struct Unlock { SRWLOCK* lock; ~Unlock(){ReleaseSRWLockExclusive(lock);} } unlock{&lock};
    static bool installed=false;
    if(installed)return;
    auto base=(uintptr_t)GetModuleHandleA(nullptr);
    auto object=(void* volatile*)(base+0x367a5b48);
    auto expected=(void**)(base+0x32d27620);
    void** actual=nullptr;SIZE_T got=0;
    if(!ReadProcessMemory(GetCurrentProcess(),(void*)object,&actual,sizeof(actual),&got) || actual!=expected)return;
    if(!ReadProcessMemory(GetCurrentProcess(),expected-1,g_http_trace_vtable,sizeof(g_http_trace_vtable),&got)
        ||got!=sizeof(g_http_trace_vtable))return;
    for(unsigned i=0;i<11;i++) {
        g_http_original_methods[i]=expected[i];
        void* observer=MakeNativeHttpObserver(i,expected[i]);
        if(!observer)return;
        g_http_trace_vtable[i+1]=observer;
    }
    if(InterlockedCompareExchangePointer(object,g_http_trace_vtable+1,expected)==expected) {
        installed=true;
        LogMsg("[NativeReceiver] installed receiver=%p original_vtable=%p cloned_vtable=%p slots=11",object,expected,g_http_trace_vtable+1);
    }
}
#ifdef MARATHON_NATIVE_TABLE_TRACE
static void InstallNativeTableCandidateTrace() {
    static std::atomic<bool> installed{false};
    if(installed.exchange(true))return;
    const uintptr_t base=(uintptr_t)GetModuleHandleA(nullptr);
    const uintptr_t tables[]={0x32da1d68,0x32da1e70,0x32da2ca0,0x32da2e10};
    for(unsigned table=0;table<4;table++)for(unsigned index=0;index<16;index++) {
        auto entry=(void* volatile*)(base+tables[table]+index*sizeof(void*));
        void* original=*entry;
        if((uintptr_t)original<base+0x2ef00000 || (uintptr_t)original>=base+0x32c80000)continue;
        const unsigned id=11+table*16+index;
        void* observer=MakeNativeHttpObserver(id,original);
        if(!observer)continue;
        DWORD old=0;
        if(!VirtualProtect((void*)entry,sizeof(void*),PAGE_READWRITE,&old))continue;
        InterlockedCompareExchangePointer(entry,observer,original);
        DWORD ignored=0;VirtualProtect((void*)entry,sizeof(void*),old,&ignored);
        LogMsg("[NativeTableCandidate] id=%u table_rva=%llx index=%u original=%p observer=%p",
               id,(unsigned long long)tables[table],index,original,observer);
    }
}
#else
static void InstallNativeTableCandidateTrace() {}
#endif
#else
static void InstallNativeHttpReceiverTrace() {}
static void InstallNativeTableCandidateTrace() {}
#endif
