#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <initializer_list>
static void LogMsg(const char*,...) { SetLastError(555);errno=77; }
#include "../client_proxy/sos_work_return_observation.h"
static unsigned calls=0;
static uintptr_t expected=20;
static __declspec(noinline) uintptr_t __fastcall Native(void* self,uintptr_t mode,uintptr_t third,uintptr_t fourth) {
    assert(self==(void*)0x12345678 && mode==7 && third==0xabcdef && fourth==0xfeedbeef);
    assert(GetLastError()==1234 && errno==21);
    ++calls;SetLastError(888);errno=34;return expected;
}
int main(int argc,char** argv) {
    assert(argc==2);
    sos_return::Capture capture{};
    capture.base=(uintptr_t)GetModuleHandleA(nullptr);
    assert(snprintf(capture.directory,MAX_PATH,"%s\\return-unit-%lu-%llu",argv[1],GetCurrentProcessId(),GetTickCount64())>0);
    assert(CreateDirectoryA(capture.directory,nullptr));
    assert(!sos_return::TryArm(Native,(void*)0x12345678,&capture));
    const uintptr_t testImage=(uintptr_t)GetModuleHandleA(nullptr);
    assert(!sos_return::TryArm((sos_return::Work)(testImage+0x309c0620),(void*)(testImage+0x3683e968),&capture));
    auto memory=(unsigned char*)VirtualAlloc((void*)0x6000367a0000ull,0x100000,MEM_RESERVE,PAGE_NOACCESS);
    assert(memory);
    assert(VirtualAlloc(memory+0x5000,4096,MEM_COMMIT,PAGE_READWRITE));
    assert(VirtualAlloc(memory+0x9e000,4096,MEM_COMMIT,PAGE_READWRITE));
    capture.base=(uintptr_t)memory-0x367a0000;
    auto task=(DWORD*)(capture.base+0x3683e9a0);
    task[0]=2;task[1]=0xffffffff;
    auto http=(DWORD*)(capture.base+0x367a5f98);
    http[0]=2;http[1]=200;
    *(unsigned long long*)(capture.base+0x367a5fb0)=313;
    for(uintptr_t value:{uintptr_t(20),uintptr_t(0),uintptr_t(0xfedcba9876543210ull)}) {
        expected=value;capture.sequence=calls+1;
        SetLastError(1234);errno=21;
        unsigned before=calls;
        assert(sos_return::Forward(Native,(void*)0x12345678,7,0xabcdef,0xfeedbeef,&capture)==value);
        assert(calls==before+1 && GetLastError()==888 && errno==34);
        char file[MAX_PATH]{};
        snprintf(file,MAX_PATH,"%s\\sos-%lu-%u-return.json",capture.directory,GetCurrentProcessId(),capture.sequence);
        HANDLE f=CreateFileA(file,GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);
        assert(f!=INVALID_HANDLE_VALUE);
        char contents[1800]{};DWORD count=0;
        assert(ReadFile(f,contents,sizeof(contents)-1,&count,nullptr));CloseHandle(f);
        char raw[90]{};snprintf(raw,sizeof(raw),"\"raw_return_hex\":\"0x%llx\"",(unsigned long long)value);
        assert(strstr(contents,raw));
        assert(strstr(contents,"\"fields_valid\":7"));
        assert(strstr(contents,"\"task_state\":2,\"task_result\":4294967295"));
        assert(task[0]==2 && task[1]==0xffffffff && http[0]==2 && http[1]==200);
    }
    // A failed evidence sink must not change arguments, the return or error state.
    strcat_s(capture.directory,"\\missing");expected=20;
    SetLastError(1234);errno=21;
    assert(sos_return::Forward(Native,(void*)0x12345678,7,0xabcdef,0xfeedbeef,&capture)==20);
    assert(calls==4 && GetLastError()==888 && errno==34);
    SetLastError(1234);errno=21;
    assert(sos_return::Invoke(Native,(void*)0x12345678,7,0xabcdef,0xfeedbeef)==20);
    assert(calls==5 && GetLastError()==888 && errno==34);
    assert(VirtualFree(memory,0,MEM_RELEASE));
    puts("SOS return observer: four arguments, full-width return, one call, error preservation, sink failure and pin rejection passed");
}
