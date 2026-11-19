#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define MARATHON_NATIVE_RECEIVER_TRACE
#include <Windows.h>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <cerrno>
#include <cassert>
static void LogMsg(const char*, ...) {}
#include "../client_proxy/native_http_receiver_trace.h"
static __declspec(noinline) uintptr_t integer_target(uintptr_t a,uintptr_t b,uintptr_t c,
                                                    uintptr_t d,uintptr_t e,uintptr_t f) {
    assert(GetLastError()==1234 && errno==21);
    assert(a==11 && b==22 && c==33 && d==44 && e==55 && f==66);
    return 0xfedcba9876543210ULL;
}
static __declspec(noinline) double vector_target(double a,double b,double c,double d,double e) {
    assert(a==1.25 && b==2.5 && c==3.75 && d==4.25 && e==5.5);
    return a+b+c+d+e;
}
int main() {
    auto integer=(decltype(&integer_target))MakeNativeHttpObserver(0,(void*)&integer_target);
    auto vector=(decltype(&vector_target))MakeNativeHttpObserver(1,(void*)&vector_target);
    assert(integer && vector);
    SetLastError(1234);errno=21;
    assert(integer(11,22,33,44,55,66)==0xfedcba9876543210ULL);
    assert(vector(1.25,2.5,3.75,4.25,5.5)==17.25);
    assert(g_http_receiver_counts[0]==1 && g_http_receiver_counts[1]==1);
    VirtualFree((void*)integer,0,MEM_RELEASE);VirtualFree((void*)vector,0,MEM_RELEASE);
}
