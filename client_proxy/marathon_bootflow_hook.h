#pragma once
#include <windows.h>
#include <atomic>
#include <cstdint>
#include <cstdio>

namespace marathon_bootflow {

// Verified RVAs for Marathon Retail RC build 26136895
constexpr uintptr_t kReferenceRva = 0x3658d650;
constexpr uintptr_t kState8TableSlotRva = 0x32DA2E50;
constexpr uintptr_t kState8OriginalTickRva = 0x30291240;
constexpr uintptr_t kState8AdvanceCallRva = 0x3029126B;

static uintptr_t g_base = 0;
static std::atomic<bool> g_started{false};
static std::atomic<bool> g_provider_forced{false};
static std::atomic<bool> g_state8_hooked{false};
static std::atomic<bool> g_state8_advanced{false};
static std::atomic<uintptr_t> g_provider_object{0};

typedef uintptr_t (__fastcall *StateTickFn)(void* context, int requested_tasks, uintptr_t r8, uintptr_t r9);
static StateTickFn g_real_state8_tick = nullptr;

static bool Read(uintptr_t address, void* out, SIZE_T bytes) {
    SIZE_T got = 0;
    return ReadProcessMemory(GetCurrentProcess(), (void*)address, out, bytes, &got) && got == bytes;
}

static uintptr_t __fastcall Hook_State8Tick(void* context, int requested_tasks, uintptr_t r8, uintptr_t r9) {
    LogMsg("[BootflowHook] State 8 tick intercepted: context=%p requested_tasks=%d r8=%p",
           context, requested_tasks, (void*)r8);

    // If requested_tasks <= 0, local content manifest is satisfied directly.
    // Advance directly to State 9 ('bootflow checking content')!
    if (requested_tasks <= 0 && !g_state8_advanced.exchange(true)) {
        typedef uintptr_t (__fastcall *AdvanceFn)(void*);
        AdvanceFn advance = (AdvanceFn)(g_base + kState8AdvanceCallRva);
        LogMsg("[BootflowHook] State 8 manifest check satisfied. Diverting to %p -> ADVANCE TO STATE 9!",
               (void*)advance);
        uintptr_t res = advance(context);
        LogMsg("[BootflowHook] Advance returned %p", (void*)res);
        return res;
    }

    if (g_real_state8_tick) {
        return g_real_state8_tick(context, requested_tasks, r8, r9);
    }
    return 0;
}

static DWORD WINAPI BootflowWorker(void*) {
    g_base = (uintptr_t)GetModuleHandleW(nullptr);
    LogMsg("[BootflowHook] Bootflow preservation worker active (base=%p)", (void*)g_base);

    ULONGLONG start = GetTickCount64();

    while (GetTickCount64() - start < 180000) { // 3 minute window
        // Phase 1: Unblock provider state 1 -> 2 automatically if reference is initialized
        if (!g_provider_forced.load()) {
            unsigned char ref[24]{};
            if (Read(g_base + kReferenceRva, ref, 24)) {
                uint64_t encoded = *(uint64_t*)ref;
                uint32_t codec = *(uint32_t*)(ref + 20);
                if (encoded && codec >= 0x1000 && codec < 0x32C84000) {
                    typedef uint64_t (*CodecFn)(uint64_t, void*);
                    CodecFn fn = (CodecFn)(g_base + codec);
                    __try {
                        uint64_t mask = fn(encoded, (void*)(g_base + kReferenceRva));
                        uintptr_t obj = (uintptr_t)(encoded ^ mask);
                        if (obj >= 0x10000 && (obj & 15) == 0) {
                            g_provider_object.store(obj, std::memory_order_release);
                            DWORD state = 0, appid = 0;
                            if (Read(obj + 0xc, &state, 4) && Read(obj + 0x78, &appid, 4) && appid == 3065800) {
                                if (state == 1) {
                                    DWORD two = 2;
                                    SIZE_T written = 0;
                                    if (WriteProcessMemory(GetCurrentProcess(), (void*)(obj + 0xc), &two, 4, &written) && written == 4) {
                                        g_provider_forced.store(true);
                                        LogMsg("[BootflowHook] Provider state forced 1 -> 2 at %p (AppID %lu)", (void*)(obj + 0xc), appid);
                                    }
                                } else if (state == 2) {
                                    g_provider_forced.store(true);
                                    LogMsg("[BootflowHook] Provider state already 2 at %p", (void*)(obj + 0xc));
                                }
                            }
                        }
                    } __except (EXCEPTION_EXECUTE_HANDLER) {}
                }
            }
        }

        // Phase 2: Hook Table 4 State 8 tick slot at 0x32DA2E50
        if (!g_state8_hooked.load()) {
            void** slot = (void**)(g_base + kState8TableSlotRva);
            void* expected = (void*)(g_base + kState8OriginalTickRva);
            void* curr = nullptr;
            if (Read((uintptr_t)slot, &curr, sizeof(void*)) && (curr == expected || curr == (void*)(g_base + kState8AdvanceCallRva))) {
                DWORD oldProtect = 0;
                if (VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &oldProtect)) {
                    g_real_state8_tick = (StateTickFn)*slot;
                    *slot = (void*)&Hook_State8Tick;
                    VirtualProtect(slot, sizeof(void*), oldProtect, &oldProtect);
                    g_state8_hooked.store(true);
                    LogMsg("[BootflowHook] Successfully hooked Table 4 State 8 slot at %p (old=%p -> new=%p)",
                           slot, curr, &Hook_State8Tick);
                }
            }
        }

        if (g_state8_advanced.load()) {
            LogMsg("[BootflowHook] State 8 advance verified complete. Worker exiting.");
            break;
        }

        Sleep(50);
    }

    return 0;
}

static void Install() {
    if (g_started.exchange(true)) return;
    HANDLE worker = CreateThread(nullptr, 0, BootflowWorker, nullptr, 0, nullptr);
    if (worker) CloseHandle(worker);
}

} // namespace marathon_bootflow
