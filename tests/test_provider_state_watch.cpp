#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <cassert>
#include <cstring>
#include <string>
#include <cstdio>
#include <cerrno>
static void LogMsg(const char*, ...) {}
#include "../client_proxy/provider_state_watch.h"
using namespace provider_watch;

struct Job {
    DWORD mainTid;
    uintptr_t address;
    unsigned stage;
    HANDLE armed, finish;
    bool armOk = false, restored = false;
};
static DWORD WINAPI ControlThread(void* parameter) {
    auto& job = *(Job*)parameter;
    auto& row = g_rows[0];
    row.thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                            THREAD_QUERY_LIMITED_INFORMATION, FALSE, job.mainTid);
    assert(row.thread);
    row.tid.store(job.mainTid);
    job.armOk = Configure(row, job.address, job.stage);
    SetEvent(job.armed);
    assert(WaitForSingleObject(job.finish, 10000) == WAIT_OBJECT_0);
    assert(Configure(row, 0, 0));
    assert(SuspendThread(row.thread) != DWORD(-1));
    CONTEXT context{}; context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    assert(GetThreadContext(row.thread, &context));
    job.restored = context.Dr0 == row.oldDr0 && (context.Dr7 & kSlotMask) == (row.oldDr7 & kSlotMask);
    ResumeThread(row.thread);
    CloseHandle(row.thread); row.thread = nullptr;
    return 0;
}
static void ExerciseHardware(uintptr_t address, unsigned stage) {
    Job job{GetCurrentThreadId(), address, stage, CreateEventW(nullptr, TRUE, FALSE, nullptr),
            CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    assert(job.armed && job.finish);
    HANDLE helper = CreateThread(nullptr, 0, ControlThread, &job, 0, nullptr); assert(helper);
    assert(WaitForSingleObject(job.armed, 10000) == WAIT_OBJECT_0 && job.armOk);
    SetLastError(1234); errno = 21;
    if (stage == 1) {
        *(volatile unsigned long long*)address = 0x1122334455667788ull;
        assert(GetLastError() == 1234 && errno == 21);
        assert(*(volatile unsigned long long*)address == 0x1122334455667788ull);
        assert(g_counts[1].load() == 1);
    } else {
        for (unsigned i = 1; i <= kEventsPerStage + 1; ++i) {
            *(volatile DWORD*)address = i;
            assert(GetLastError() == 1234 && errno == 21);
            assert(*(volatile DWORD*)address == i);
        }
        // The event-limit hit self-restores; the next write is not trapped.
        assert(g_counts[2].load() == kEventsPerStage && !g_rows[0].owned.load());
    }
    SetEvent(job.finish);
    assert(WaitForSingleObject(helper, 10000) == WAIT_OBJECT_0 && job.restored);
    CloseHandle(helper); CloseHandle(job.armed); CloseHandle(job.finish);
}
static void ExerciseImmediateHandoff(unsigned char* object) {
    // Test-owned virtual reservation gives the generated publisher the exact RVAs
    // required by the production guard. No game or other process is involved.
    const uintptr_t previousBase = g_base;
    auto image = (unsigned char*)VirtualAlloc(nullptr, kReferenceRva + 0x10000, MEM_RESERVE, PAGE_NOACCESS);
    assert(image);
    g_base = (uintptr_t)image;
    auto code = (unsigned char*)VirtualAlloc(image+0x311a0000, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    auto referencePage = (unsigned char*)VirtualAlloc(image+0x3658d000, 4096, MEM_COMMIT, PAGE_READWRITE);
    assert(code && referencePage);
    auto reference = referencePage+0x650;
    const unsigned long long mask = 0x1122334455667788ull;
    const unsigned long long encoded = (uintptr_t)object ^ mask;
    std::string body;
    body.append("\x56\x41\x54\x41\x56\x41\x57",7); // preserve RSI,R12,R14,R15
    auto immediate = [&](const char* opcode, unsigned long long value) {
        body.append(opcode,2); body.append((const char*)&value,8);
    };
    immediate("\x49\xbe",encoded); immediate("\x49\xbf",(uintptr_t)reference);
    immediate("\x48\xbe",kAllocationBytes); immediate("\x49\xbc",g_base);
    immediate("\x48\xb8",mask); immediate("\x48\xba",(uintptr_t)reference);
    const unsigned start = 0x880;
    assert(body.size() < 0x932-start);
    body.resize(0x932-start,'\x90');
    body.append("\x4d\x89\x37",3); // post-instruction RIP is exactly +0x311a0935
    immediate("\x48\xba",(uintptr_t)object);
    body.append("\xc7\x42\x0c\x00\x00\x00\x00",7);
    body.append("\xc7\x42\x0c\x01\x00\x00\x00",7);
    body.append("\xc7\x42\x0c\x02\x00\x00\x00",7);
    body.append("\x41\x5f\x41\x5e\x41\x5c\x5e\xc3",8);
    memcpy(code+start,body.data(),body.size());
    assert(FlushInstructionCache(GetCurrentProcess(),code+start,body.size()));
    CONTEXT publication{};
    publication.Rip=g_base+kPublicationReturnRva; publication.R15=(uintptr_t)reference;
    publication.Rdx=(uintptr_t)reference; publication.R12=g_base;
    publication.Rsi=kAllocationBytes; publication.R14=encoded; publication.Rax=mask;
    memcpy(reference,&encoded,8);
    Control candidate{};
    assert(PublicationObject(&publication,&candidate) && candidate.object==(uintptr_t)object);
    publication.Rip++; assert(!PublicationObject(&publication,&candidate)); publication.Rip--;
    publication.Rsi=4; assert(!PublicationObject(&publication,&candidate)); publication.Rsi=kAllocationBytes;
    publication.R14++; assert(!PublicationObject(&publication,&candidate)); publication.R14--;
    publication.Rax=encoded; assert(!PublicationObject(&publication,&candidate)); publication.Rax=mask;
    *(unsigned long long*)reference=0;
    for (auto& event:g_events) { event.ready.store(false); event.flushed=false; }
    g_counts[1].store(0); g_counts[2].store(0); g_sequence.store(0);
    g_autoClaimed.store(false); g_autoObject.store(0);
    wchar_t previousDirectory[MAX_PATH]{}; wcscpy_s(previousDirectory,g_directory);
    assert(swprintf_s(g_directory,L"%s\\automatic",previousDirectory)>0);
    assert(CreateDirectoryW(g_directory,nullptr));
    *(DWORD*)(object+0xc)=0x1234;
    Job job{GetCurrentThreadId(),(uintptr_t)reference,1,CreateEventW(nullptr,TRUE,FALSE,nullptr),
            CreateEventW(nullptr,TRUE,FALSE,nullptr)};
    HANDLE helper=CreateThread(nullptr,0,ControlThread,&job,0,nullptr); assert(helper);
    assert(WaitForSingleObject(job.armed,10000)==WAIT_OBJECT_0 && job.armOk);
    SetLastError(1234); errno=21;
    ((void(*)())(code+start))();
    assert(GetLastError()==1234 && errno==21);
    assert(g_autoObject.load()==(uintptr_t)object);
    assert(g_rows[0].stage.load()==2 && !g_rows[0].pendingHandoff.load());
    assert(g_counts[1].load()==1 && g_counts[2].load()==3 && g_sequence.load()==4);
    for (unsigned i=0;i<3;++i) {
        assert(g_events[i+1].ready.load() && g_events[i+1].stage==2);
        assert(g_events[i+1].value==i && g_events[i+1].address==(uintptr_t)object+0xc);
    }
    assert(*(DWORD*)(object+0xc)==2);
    SetEvent(job.finish);
    assert(WaitForSingleObject(helper,10000)==WAIT_OBJECT_0 && job.restored);
    CloseHandle(helper); CloseHandle(job.armed); CloseHandle(job.finish);
    Flush(); assert(g_outputFailures.load()==0);
    wcscpy_s(g_directory,previousDirectory);
    g_autoObject.store(0); g_autoClaimed.store(false); g_base=previousBase;
    assert(VirtualFree(image,0,MEM_RELEASE));
    std::puts("publication handoff: immediate same-thread state writes 0,1,2 captured; provenance guards and restoration passed");
}
int main(int argc, char** argv) {
    assert(argc == 2);
    wchar_t parent[MAX_PATH]{};
    assert(MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, parent, MAX_PATH));
    assert(swprintf_s(g_directory, L"%s\\provider-unit-%lu-%llu", parent, GetCurrentProcessId(),
                      GetTickCount64()) > 0);
    assert(CreateDirectoryW(g_directory, nullptr));
    g_base = (uintptr_t)GetModuleHandleW(nullptr);
    assert(!PinExecutable()); // A test executable must never pass the production pin.
    auto object = (unsigned char*)VirtualAlloc(nullptr, 8192, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    assert(object);
    *(DWORD*)(object+0xc) = 1; *(DWORD*)(object+0xbc) = 2; *(DWORD*)(object+0x78) = 3065800;
    Control control{}; control.object = (uintptr_t)object;
    assert(ValidateObject(control));
    *(DWORD*)(object+0x78) = 123; assert(!ValidateObject(control));
    *(DWORD*)(object+0x78) = 3065800;
    unsigned char reference[24]; for (unsigned i=0;i<24;++i) reference[i]=(unsigned char)i;
    char hex[49]{}; for (unsigned i=0;i<24;++i) sprintf_s(hex+i*2,3,"%02x",reference[i]);
    char text[512]{};
    int length = sprintf_s(text,"provider-state-watch-v1\npid %lu\nbase %llx\nobject %llx\nrecord %s\n",
                          GetCurrentProcessId(), (unsigned long long)g_base,
                          (unsigned long long)object, hex);
    assert(ParseControl(text,length,GetCurrentProcessId(),g_base,reference,&control));
    assert(!ParseControl(text,length,GetCurrentProcessId()+1,g_base,reference,&control));
    reference[0]^=1;
    assert(!ParseControl(text,length,GetCurrentProcessId(),g_base,reference,&control));
    reference[0]^=1;
    std::string trailing = std::string(text,length)+"unexpected";
    assert(!ParseControl(trailing.data(),trailing.size(),GetCurrentProcessId(),g_base,reference,&control));
    auto nullCharacter = std::string(text,length); nullCharacter[0] = '\0';
    assert(!ParseControl(nullCharacter.data(),nullCharacter.size(),GetCurrentProcessId(),g_base,reference,&control));
    assert(!ValidateObject(Control{}));
    CONTEXT fake{}; EXCEPTION_RECORD exception{}; EXCEPTION_POINTERS pointers{&exception,&fake};
    exception.ExceptionCode = EXCEPTION_ACCESS_VIOLATION;
    assert(Observe(&pointers) == EXCEPTION_CONTINUE_SEARCH);
    exception.ExceptionCode = EXCEPTION_SINGLE_STEP; fake.Dr6 = 1; fake.Dr0 = 0x1234;
    assert(Observe(&pointers) == EXCEPTION_CONTINUE_SEARCH);
    g_handler = AddVectoredExceptionHandler(1, Observe); assert(g_handler);
    alignas(8) volatile unsigned long long publication = 0;
    ExerciseHardware((uintptr_t)&publication,1);
    ExerciseHardware((uintptr_t)(object+0xc),2);
    assert(g_sequence.load() == 1+kEventsPerStage);
    for (unsigned i=0;i<1+kEventsPerStage;++i) {
        assert(g_events[i].ready.load());
        assert(g_events[i].context.Rip && g_events[i].codeBytes && g_events[i].stackBytes);
        assert(g_events[i].valueBytes == (i==0 ? 8 : 4));
        assert(g_events[i].value == (i==0 ? 0x1122334455667788ull : i));
    }
    Flush();
    assert(g_outputFailures.load() == 0);
    for (unsigned i=0;i<1+kEventsPerStage;++i) assert(g_events[i].flushed);
    ExerciseImmediateHandoff(object);
    // Other simultaneous debug reasons must remain available to their owner.
    Row& row=g_rows[0]; row.address.store((uintptr_t)object+0xc); row.stage.store(2);
    row.oldDr0=0x12345678; row.oldDr7=0; row.owned.store(true);
    g_stopping.store(true); fake.Dr0=row.address.load(); fake.Dr7=kWrite4;
    fake.Dr6=1|(1ull<<14); fake.Dr1=0x87654321;
    assert(Observe(&pointers)==EXCEPTION_CONTINUE_SEARCH);
    assert(fake.Dr0==0x12345678 && fake.Dr1==0x87654321 && !(fake.Dr6&1) && (fake.Dr6&(1ull<<14)));
    assert(RemoveVectoredExceptionHandler(g_handler)); g_handler=nullptr;
    assert(VirtualFree(object,0,MEM_RELEASE));
    std::puts("provider watcher: hardware events, value/error preservation, limits, ownership, parser, and restoration passed");
}
