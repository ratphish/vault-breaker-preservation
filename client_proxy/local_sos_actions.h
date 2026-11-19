#pragma once
#ifdef MARATHON_LOCAL_SOS_ROUTING
// Historical name: slot 3 is native initialization, not SOS action execution.
// Saved entry/return evidence shows it runs before the SignOn HTTP request.
// Never wait for that request here or replace initialization with success.
using NativeSosWork=uintptr_t(__fastcall*)(void*,uintptr_t,uintptr_t,uintptr_t);
#ifdef MARATHON_SOS_RETURN_OBSERVE
#include "sos_work_return_observation.h"
#endif
static NativeSosWork g_native_sos_work=nullptr;
static void* g_local_sos_vtable[10]={};
static uintptr_t __fastcall HandleLocalSosActions(void* receiver,uintptr_t mode,uintptr_t third,uintptr_t fourth) {
#ifdef MARATHON_SOS_RETURN_OBSERVE
    return sos_return::Invoke(g_native_sos_work,receiver,mode,third,fourth);
#else
    return g_native_sos_work(receiver,mode,third,fourth);
#endif
}
static void InstallLocalSosActions() {
    static SRWLOCK lock=SRWLOCK_INIT;
    if(!TryAcquireSRWLockExclusive(&lock))return;
    struct Unlock { SRWLOCK* lock;~Unlock(){ReleaseSRWLockExclusive(lock);} } unlock{&lock};
    static bool installed=false;if(installed)return;
    const uintptr_t base=(uintptr_t)GetModuleHandleA(nullptr);
    auto receiver=(void* volatile*)(base+0x3683e968);
    auto expected=(void**)(base+0x32da9f28);
    void** actual=nullptr;SIZE_T count=0;
    if(!ReadProcessMemory(GetCurrentProcess(),(void*)receiver,&actual,sizeof(actual),&count)||actual!=expected)return;
    if(!ReadProcessMemory(GetCurrentProcess(),expected-1,g_local_sos_vtable,sizeof(g_local_sos_vtable),&count)||count!=sizeof(g_local_sos_vtable))return;
    if(expected[3]!=(void*)(base+0x309c0620))return;
    g_native_sos_work=(NativeSosWork)expected[3];
    g_local_sos_vtable[4]=(void*)&HandleLocalSosActions;
    if(InterlockedCompareExchangePointer(receiver,g_local_sos_vtable+1,expected)==expected) {
        installed=true;
        LogMsg("[LocalSOS] native initialization passthrough receiver=%p original=%p",receiver,g_native_sos_work);
    }
}
#else
static void InstallLocalSosActions() {}
#endif
