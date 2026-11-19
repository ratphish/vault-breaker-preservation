#pragma once
#include <Windows.h>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cerrno>

// Opt-in observation of the existing four-argument NativeSosWork call. No
// target-field writes, debugger, hardware watches, native decoder calls or
// completion substitution. Raw return values are not success assertions.
namespace sos_return {
using Work = uintptr_t(__fastcall*)(void*, uintptr_t, uintptr_t, uintptr_t);
struct Capture { uintptr_t base=0; char directory[MAX_PATH]{}; unsigned sequence=1; };
struct Fields {
    DWORD task[2]{}, http[2]{};
    unsigned long long received=0;
    unsigned valid=0;
};
static std::atomic<bool> g_claimed{false};
static bool Read(uintptr_t address, void* out, SIZE_T bytes) {
    SIZE_T read=0;
    return ReadProcessMemory(GetCurrentProcess(),(void*)address,out,bytes,&read) && read==bytes;
}
static Fields Snapshot(uintptr_t base) {
    Fields f;
    if(Read(base+0x3683e9a0,f.task,sizeof(f.task)))f.valid|=1;
    if(Read(base+0x367a5f98,f.http,sizeof(f.http)))f.valid|=2;
    if(Read(base+0x367a5fb0,&f.received,sizeof(f.received)))f.valid|=4;
    return f;
}
static bool Save(const Capture& capture,const char* suffix,const void* bytes,DWORD size) {
    char path[MAX_PATH]{},temp[MAX_PATH]{};
    if(snprintf(path,sizeof(path),"%s\\sos-%lu-%u-%s",capture.directory,GetCurrentProcessId(),capture.sequence,suffix)<0 ||
       strlen(path)+5>=MAX_PATH)return false;
    snprintf(temp,sizeof(temp),"%s.tmp",path);
    HANDLE file=CreateFileA(temp,GENERIC_WRITE,FILE_SHARE_READ,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(file==INVALID_HANDLE_VALUE)return false;
    DWORD count=0;
    bool ok=WriteFile(file,bytes,size,&count,nullptr) && count==size;
    CloseHandle(file);
    // Publish complete records atomically, never overwrite older evidence.
    return ok && MoveFileA(temp,path);
}
static unsigned SaveCode(const Capture& capture,const char* phase) {
    const uintptr_t pages[]={0x309c0000,0x305e1000,0x3021a000,0x32d27000,0x2f9aa000};
    unsigned failures=0;
    unsigned char buffer[4096];
    for(auto rva:pages) {
        char suffix[80]{};
        snprintf(suffix,sizeof(suffix),"%s-page-%08llx.bin",phase,(unsigned long long)rva);
        if(!Read(capture.base+rva,buffer,sizeof(buffer)) || !Save(capture,suffix,buffer,sizeof(buffer)))++failures;
    }
    return failures;
}
static bool TryArm(Work work,void* receiver,Capture* capture) {
    const uintptr_t base=(uintptr_t)GetModuleHandleA(nullptr);
    if((uintptr_t)work!=base+0x309c0620 || (uintptr_t)receiver!=base+0x3683e968 || g_claimed.load())return false;
    char executable[MAX_PATH]{};
    if(!GetModuleFileNameA(nullptr,executable,MAX_PATH) ||
       _stricmp(executable,"D:\\Marathon-live\\Marathon.exe"))return false;
    Capture candidate{};candidate.base=base;
    DWORD length=GetEnvironmentVariableA("MARATHON_SOS_RETURN_DIR",candidate.directory,MAX_PATH);
    if(!length || length>MAX_PATH-90)return false;
    char arm[MAX_PATH]{};snprintf(arm,sizeof(arm),"%s\\ARM_SOS_RETURN",candidate.directory);
    DWORD attributes=GetFileAttributesA(arm);
    if(attributes==INVALID_FILE_ATTRIBUTES || (attributes&FILE_ATTRIBUTE_DIRECTORY))return false;
    if(g_claimed.exchange(true))return false;
    *capture=candidate;return true;
}
static uintptr_t Forward(Work work,void* receiver,uintptr_t mode,uintptr_t third,uintptr_t fourth,
                         const Capture* capture) {
    const DWORD entryError=GetLastError();
    const int entryErrno=errno;
    ULONGLONG tick=0;
    if(capture) {
        tick=GetTickCount64();
        Fields before=Snapshot(capture->base);
        unsigned failures=SaveCode(*capture,"entry");
        char json[1500]{};
        int size=snprintf(json,sizeof(json),
            "{\"version\":1,\"phase\":\"entry\",\"pid\":%lu,\"tid\":%lu,\"tick\":%llu,"
            "\"image_base\":\"0x%llx\",\"native_work_rva\":\"0x309c0620\",\"receiver\":\"0x%llx\","
            "\"mode\":%llu,\"third\":\"0x%llx\",\"fourth\":\"0x%llx\",\"fields_valid\":%u,"
            "\"task_state\":%lu,\"task_result\":%lu,\"http_state\":%lu,\"http_status\":%lu,"
            "\"received_bytes\":%llu,\"code_capture_failures\":%u}",
            GetCurrentProcessId(),GetCurrentThreadId(),tick,(unsigned long long)capture->base,
            (unsigned long long)receiver,(unsigned long long)mode,(unsigned long long)third,(unsigned long long)fourth,
            before.valid,before.task[0],before.task[1],before.http[0],before.http[1],before.received,failures);
        bool saved=size>0 && size<(int)sizeof(json) && Save(*capture,"entry.json",json,(DWORD)size);
        LogMsg("[SOSReturn] entry receiver=%p work=%p mode=%llu saved=%u",receiver,(void*)work,
               (unsigned long long)mode,saved?1:0);
    }
    errno=entryErrno;SetLastError(entryError);
    const uintptr_t raw=work(receiver,mode,third,fourth); // exactly one original call
    const DWORD nativeError=GetLastError();
    const int nativeErrno=errno;
    if(capture) {
        const ULONGLONG returned=GetTickCount64();
        Fields after=Snapshot(capture->base);
        unsigned failures=SaveCode(*capture,"return");
        char json[1500]{};
        int size=snprintf(json,sizeof(json),
            "{\"version\":1,\"phase\":\"return\",\"pid\":%lu,\"tid\":%lu,\"tick\":%llu,"
            "\"duration_ms\":%llu,\"image_base\":\"0x%llx\",\"native_work_rva\":\"0x309c0620\","
            "\"raw_return_hex\":\"0x%llx\",\"return_low32\":%lu,\"last_error\":%lu,\"errno\":%d,"
            "\"fields_valid\":%u,\"task_state\":%lu,\"task_result\":%lu,\"http_state\":%lu,"
            "\"http_status\":%lu,\"received_bytes\":%llu,\"code_capture_failures\":%u,"
            "\"scope\":\"Raw original-work return before wrapper publication; no success assertion\"}",
            GetCurrentProcessId(),GetCurrentThreadId(),returned,returned-tick,(unsigned long long)capture->base,
            (unsigned long long)raw,(DWORD)raw,nativeError,nativeErrno,after.valid,after.task[0],after.task[1],
            after.http[0],after.http[1],after.received,failures);
        bool saved=size>0 && size<(int)sizeof(json) && Save(*capture,"return.json",json,(DWORD)size);
        LogMsg("[SOSReturn] raw_return=0x%llx low32=%lu task=%lu result=%lu http=%lu/%lu saved=%u",
               (unsigned long long)raw,(DWORD)raw,after.task[0],after.task[1],after.http[0],after.http[1],saved?1:0);
    }
    errno=nativeErrno;SetLastError(nativeError);
    return raw;
}
static uintptr_t Invoke(Work work,void* receiver,uintptr_t mode,uintptr_t third,uintptr_t fourth) {
    const DWORD error=GetLastError();const int crtError=errno;
    Capture capture{};
    const bool armed=TryArm(work,receiver,&capture);
    errno=crtError;SetLastError(error);
    return Forward(work,receiver,mode,third,fourth,armed?&capture:nullptr);
}
} // namespace sos_return
