#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define MARATHON_STATE_RECEIVER_TRACE
#include <Windows.h>
#include <intrin.h>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <cerrno>
#include <cassert>
static void LogMsg(const char*,...) {}
#include "../client_proxy/state_writer_observation.h"
int main(int argc,char** argv) {
    assert(argc==2);
    assert(GetFullPathNameA(argv[1],MAX_PATH,g_detail_directory,nullptr));
    auto memory=(volatile unsigned char*)VirtualAlloc(nullptr,4096,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    assert(memory);
    g_detail_mapping=(uintptr_t)memory;
    void* handler=AddVectoredExceptionHandler(1,ObserveDetailWriter);assert(handler);
    DWORD old=0;assert(VirtualProtect((void*)memory,4096,PAGE_READWRITE|PAGE_GUARD,&old));
    SetLastError(1234);errno=21;
    *memory=42;
    assert(*memory==42 && g_detail_observations==1);
    assert(GetLastError()==1234 && errno==21);
    MEMORY_BASIC_INFORMATION info{};assert(VirtualQuery((void*)memory,&info,sizeof(info)));
    assert(!(info.Protect&PAGE_GUARD));
    *memory=43;assert(g_detail_observations==1);
    assert(RemoveVectoredExceptionHandler(handler));
    assert(VirtualFree((void*)memory,0,MEM_RELEASE));
}
