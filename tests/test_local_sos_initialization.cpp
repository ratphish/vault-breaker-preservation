#define WIN32_LEAN_AND_MEAN
#define MARATHON_LOCAL_SOS_ROUTING
#include <Windows.h>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cerrno>
static void LogMsg(const char*,...) {}
#include "../client_proxy/local_sos_actions.h"

static unsigned calls=0;
static uintptr_t __fastcall Initialize(void* receiver,uintptr_t mode,uintptr_t third,uintptr_t fourth) {
    assert(receiver==(void*)((uintptr_t)GetModuleHandleA(nullptr)+0x3683e968));
    assert(mode==7 && third==0xabcdef && fourth==0xfeedbeef);
    assert(GetLastError()==1234 && errno==21);
    ++calls;SetLastError(888);errno=34;
    return 0xfedcba9876543210ull;
}
int main() {
    // Run from the isolated artifact directory, never the game directory.
    CreateDirectoryA("config",nullptr);
    FILE* fixture=nullptr;
    assert(fopen_s(&fixture,"config\\local_sos_actions.json","wb")==0);
    assert(fputs("{\"actions\":[]}",fixture)>=0);
    assert(fclose(fixture)==0);
    const uintptr_t base=(uintptr_t)GetModuleHandleA(nullptr);
    // Standalone test process only: HTTP state must not gate or skip setup.
    auto page=(unsigned char*)VirtualAlloc((void*)(base+0x367a5000),4096,
        MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    assert(page);
    g_native_sos_work=Initialize;
    for(unsigned completed=0;completed!=2;++completed) {
        *(DWORD*)(page+0xf98)=completed?2:0;
        *(DWORD*)(page+0xf9c)=completed?200:0;
        *(unsigned long long*)(page+0xfb0)=completed?313:0;
        SetLastError(1234);errno=21;
        auto result=HandleLocalSosActions((void*)(base+0x3683e968),7,0xabcdef,0xfeedbeef);
        assert(result==0xfedcba9876543210ull && calls==completed+1);
        assert(GetLastError()==888 && errno==34);
    }
    assert(VirtualFree(page,0,MEM_RELEASE));
    puts("Native initialization forwarded exactly once for pending and completed HTTP states.");
}
