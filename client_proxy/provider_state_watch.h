#pragma once
// Opt-in adaptation of state_task_watch.h. No target data/code writes, API
// replacement, native decoder calls, exception swallowing, or phase advancement.
#include <Windows.h>
#include <TlHelp32.h>
#include <wincrypt.h>
#include <intrin.h>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cerrno>

namespace provider_watch {
constexpr uintptr_t kReferenceRva = 0x3658d650;
constexpr uintptr_t kPublicationReturnRva = 0x311a0935;
constexpr SIZE_T kAllocationBytes = 0x10c8;
constexpr DWORD64 kSlotMask = 0xf0003ull;
constexpr DWORD64 kWrite4 = 0xd0001ull, kWrite8 = 0x90001ull;
constexpr unsigned kThreads = 128, kEventsPerStage = 16, kEvents = 32;
constexpr DWORD kRunMs = 300000, kStateMs = 180000;
constexpr unsigned kStackBytes = 4096, kCodeBytes = 512;
static const unsigned char kExecutableHash[32] = {
    0xd5,0xc2,0xfb,0x53,0x8f,0x40,0x20,0xa7,0x10,0x60,0xb5,0x53,0x12,0x72,0x59,0xfc,
    0xd5,0xd3,0x13,0x1b,0xeb,0x89,0xa4,0xec,0x26,0xa7,0xd6,0xcc,0xfa,0x9d,0xfb,0xfd
};
struct Row {
    std::atomic<DWORD> tid{0};
    HANDLE thread = nullptr;
    DWORD64 oldDr0 = 0, oldDr7 = 0;
    std::atomic<uintptr_t> address{0};
    std::atomic<unsigned> stage{0};
    std::atomic<bool> owned{false};
    std::atomic<bool> handling{false}, pendingHandoff{false};
};
struct Event {
    std::atomic<bool> ready{false};
    bool flushed = false;
    unsigned sequence = 0, stage = 0;
    DWORD tid = 0;
    ULONGLONG tick = 0;
    uintptr_t address = 0, codeAddress = 0;
    DWORD64 value = 0;
    SIZE_T valueBytes = 0, referenceBytes = 0, stackBytes = 0, codeBytes = 0;
    unsigned char reference[24]{};
    CONTEXT context{};
    unsigned char stack[kStackBytes]{}, code[kCodeBytes]{};
};
struct Control { uintptr_t object = 0; unsigned char reference[24]{}; };
static Row g_rows[kThreads];
static Event g_events[kEvents];
static std::atomic<unsigned> g_counts[3], g_sequence{0};
static std::atomic<unsigned> g_outputFailures{0};
static std::atomic<bool> g_stopping{false}, g_started{false};
static std::atomic<bool> g_autoClaimed{false};
static std::atomic<uintptr_t> g_autoObject{0};
static Control g_autoControl{};
static ULONGLONG g_autoTick = 0;
static uintptr_t g_base = 0;
static wchar_t g_directory[MAX_PATH]{};
static void* g_handler = nullptr;

static bool Read(uintptr_t address, void* out, SIZE_T bytes) {
    SIZE_T got = 0;
    return ReadProcessMemory(GetCurrentProcess(), (void*)address, out, bytes, &got) && got == bytes;
}
static bool Path(wchar_t* out, const wchar_t* suffix) {
    return swprintf_s(out, MAX_PATH, L"%s\\%s", g_directory, suffix) > 0;
}
static bool Exists(const wchar_t* suffix) {
    wchar_t path[MAX_PATH]{};
    if (!Path(path, suffix)) return false;
    DWORD attributes = GetFileAttributesW(path);
    return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
}
static bool Save(const wchar_t* suffix, const void* data, DWORD size) {
    wchar_t path[MAX_PATH]{};
    if (!Path(path, suffix)) return false;
    HANDLE file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_NEW,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    bool ok = WriteFile(file, data, size, &written, nullptr) && written == size;
    CloseHandle(file);
    return ok;
}
static DWORD64 Bits(unsigned stage) { return stage == 1 ? kWrite8 : kWrite4; }
static void RestoreContext(CONTEXT* context, Row& row) {
    context->Dr0 = row.oldDr0;
    context->Dr7 = (context->Dr7 & ~kSlotMask) | (row.oldDr7 & kSlotMask);
    row.owned.store(false, std::memory_order_release);
    row.pendingHandoff.store(false, std::memory_order_release);
}
static bool PublicationObject(const CONTEXT* context, Control* result) {
    // This identity precedes constructor fields such as AppID and state. Bind to
    // the captured allocator instruction and registers, never to a guessed heap address.
    if (context->Rip != g_base + kPublicationReturnRva ||
        context->R15 != g_base + kReferenceRva || context->Rdx != context->R15 ||
        context->R12 != g_base || context->Rsi != kAllocationBytes || !context->R14) return false;
    unsigned char instruction[3]{};
    if (!Read(context->Rip - 3, instruction, sizeof(instruction)) ||
        memcmp(instruction, "\x4d\x89\x37", 3)) return false;
    Control candidate{};
    if (!Read(g_base + kReferenceRva, candidate.reference, sizeof(candidate.reference))) return false;
    DWORD64 encoded = 0;
    memcpy(&encoded, candidate.reference, sizeof(encoded));
    if (encoded != context->R14) return false;
    candidate.object = (uintptr_t)(context->R14 ^ context->Rax);
    if (candidate.object < 0x10000 || candidate.object >= 0x800000000000ull - kAllocationBytes ||
        (candidate.object & 15)) return false;
    MEMORY_BASIC_INFORMATION info{};
    if (!VirtualQuery((void*)candidate.object, &info, sizeof(info)) || info.State != MEM_COMMIT ||
        info.Type != MEM_PRIVATE || (info.Protect & (PAGE_NOACCESS | PAGE_GUARD)) ||
        !(info.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) ||
        candidate.object + kAllocationBytes > (uintptr_t)info.BaseAddress + info.RegionSize) return false;
    *result = candidate;
    return true;
}
static LONG CALLBACK Observe(EXCEPTION_POINTERS* exception) {
    auto context = exception->ContextRecord;
    if (exception->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP || !(context->Dr6 & 1))
        return EXCEPTION_CONTINUE_SEARCH;
    const DWORD lastError = GetLastError();
    const int crtError = errno;
    const DWORD tid = GetCurrentThreadId();
    Row* row = nullptr;
    for (auto& candidate : g_rows) {
        if (candidate.tid.load(std::memory_order_acquire) == tid && candidate.owned.load(std::memory_order_acquire) &&
            context->Dr0 == candidate.address.load(std::memory_order_acquire) &&
            (context->Dr7 & kSlotMask) == Bits(candidate.stage.load())) { row = &candidate; break; }
    }
    if (!row) { errno = crtError; SetLastError(lastError); return EXCEPTION_CONTINUE_SEARCH; }
    row->handling.store(true, std::memory_order_release);
    const DWORD64 otherReasons = context->Dr6 & (0xeull | (7ull << 13));
    const unsigned stage = row->stage.load();
    if (stage == 2) row->pendingHandoff.store(false, std::memory_order_release);
    if (!g_stopping.load(std::memory_order_acquire)) {
        const unsigned ordinal = g_counts[stage].fetch_add(1);
        if (ordinal < kEventsPerStage) {
            const unsigned slot = g_sequence.fetch_add(1);
            if (slot < kEvents) {
                auto& event = g_events[slot];
                event.sequence = slot + 1; event.stage = stage; event.tid = tid;
                event.tick = GetTickCount64(); event.address = context->Dr0;
                event.context = *context;
                const SIZE_T size = stage == 1 ? 8 : 4;
                ReadProcessMemory(GetCurrentProcess(), (void*)event.address, &event.value, size, &event.valueBytes);
                ReadProcessMemory(GetCurrentProcess(), (void*)(g_base + kReferenceRva), event.reference,
                                  sizeof(event.reference), &event.referenceBytes);
                const uintptr_t top = __readgsqword(8);
                const SIZE_T available = top > context->Rsp ? top - context->Rsp : 0;
                const SIZE_T stackSize = available < kStackBytes ? available : kStackBytes;
                if (stackSize) ReadProcessMemory(GetCurrentProcess(), (void*)context->Rsp, event.stack,
                                                stackSize, &event.stackBytes);
                event.codeAddress = context->Rip >= 128 ? context->Rip - 128 : context->Rip;
                ReadProcessMemory(GetCurrentProcess(), (void*)event.codeAddress, event.code,
                                  sizeof(event.code), &event.codeBytes);
                // The VEH uses fixed storage only. The helper performs all file/log IO.
                event.ready.store(true, std::memory_order_release);
            }
        }
    }
    if (stage == 1 && !otherReasons && !g_stopping.load(std::memory_order_acquire)) {
        Control candidate{};
        if (PublicationObject(context, &candidate) && !g_autoClaimed.exchange(true)) {
            g_autoControl = candidate;
            g_autoTick = GetTickCount64();
            // Change the faulting thread's resume context, so its very next
            // memset/constructor write is watched without a helper-thread race.
            row->pendingHandoff.store(true, std::memory_order_release);
            row->address.store(candidate.object + 0xc);
            row->stage.store(2);
            context->Dr0 = candidate.object + 0xc;
            context->Dr7 = (context->Dr7 & ~kSlotMask) | kWrite4;
            g_autoObject.store(candidate.object, std::memory_order_release);
        }
    }
    context->Dr6 &= ~1ull;
    if (g_stopping.load() || g_counts[row->stage.load()].load() >= kEventsPerStage) RestoreContext(context, *row);
    row->handling.store(false, std::memory_order_release);
    errno = crtError; SetLastError(lastError);
    return otherReasons ? EXCEPTION_CONTINUE_SEARCH : EXCEPTION_CONTINUE_EXECUTION;
}
static bool Configure(Row& row, uintptr_t address, unsigned stage) {
    if (row.handling.load(std::memory_order_acquire) || row.pendingHandoff.load(std::memory_order_acquire)) return false;
    if (SuspendThread(row.thread) == DWORD(-1)) return false;
    if (row.handling.load(std::memory_order_acquire) || row.pendingHandoff.load(std::memory_order_acquire)) {
        ResumeThread(row.thread); return false;
    }
    CONTEXT context{}; context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    bool ok = GetThreadContext(row.thread, &context) != FALSE;
    const bool owned = row.owned.load(std::memory_order_acquire);
    // A pending owned trap must reach the VEH; do not revoke its ownership first.
    if (ok && owned && (context.Dr6 & 1)) { ResumeThread(row.thread); return false; }
    if (ok && owned && (context.Dr0 != row.address.load() ||
                        (context.Dr7 & kSlotMask) != Bits(row.stage.load()))) {
        // Never overwrite somebody else's debug-register changes.
        row.owned.store(false); ok = false;
    }
    if (ok && !owned && (context.Dr7 & 3)) ok = false;
    if (ok && !address) {
        if (owned) {
            CONTEXT restored = context;
            restored.Dr0 = row.oldDr0;
            restored.Dr7 = (restored.Dr7 & ~kSlotMask) | (row.oldDr7 & kSlotMask);
            ok = SetThreadContext(row.thread, &restored) != FALSE;
            if (ok) row.owned.store(false, std::memory_order_release);
        }
    } else if (ok) {
        if (!owned) { row.oldDr0 = context.Dr0; row.oldDr7 = context.Dr7; }
        const uintptr_t oldAddress = row.address.load();
        const unsigned oldStage = row.stage.load();
        row.address.store(address); row.stage.store(stage);
        context.Dr0 = address;
        context.Dr7 = (context.Dr7 & ~kSlotMask) | Bits(stage);
        row.owned.store(true, std::memory_order_release);
        ok = SetThreadContext(row.thread, &context) != FALSE;
        if (!ok) { row.address.store(oldAddress); row.stage.store(oldStage); row.owned.store(owned); }
    }
    ResumeThread(row.thread);
    return ok;
}
static unsigned Scan(uintptr_t address, unsigned stage) {
    const uintptr_t automatic = g_autoObject.load(std::memory_order_acquire);
    if (address && automatic) { address = automatic + 0xc; stage = 2; }
    const DWORD self = GetCurrentThreadId();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot != INVALID_HANDLE_VALUE && address) {
        THREADENTRY32 entry{}; entry.dwSize = sizeof(entry);
        for (BOOL more = Thread32First(snapshot, &entry); more; more = Thread32Next(snapshot, &entry)) {
            if (entry.th32OwnerProcessID != GetCurrentProcessId() || entry.th32ThreadID == self) continue;
            Row* row = nullptr; bool known = false;
            for (auto& candidate : g_rows) {
                if (candidate.tid.load() == entry.th32ThreadID) { known = true; break; }
                if (!candidate.tid.load() && !row) row = &candidate;
            }
            if (known || !row) continue;
            HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                                       THREAD_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ThreadID);
            if (!thread) continue;
            if (GetProcessIdOfThread(thread) != GetCurrentProcessId()) { CloseHandle(thread); continue; }
            row->thread = thread; row->tid.store(entry.th32ThreadID, std::memory_order_release);
        }
    }
    if (snapshot != INVALID_HANDLE_VALUE) CloseHandle(snapshot);
    unsigned armed = 0;
    for (auto& row : g_rows) {
        if (!row.thread) continue;
        DWORD exitCode = 0;
        if (!GetExitCodeThread(row.thread, &exitCode) || exitCode != STILL_ACTIVE) {
            row.owned.store(false); continue;
        }
        if (address && row.owned.load() && row.address.load() == address && row.stage.load() == stage) {
            ++armed; continue;
        }
        if (address || row.owned.load()) Configure(row, address, stage);
        if (row.owned.load()) ++armed;
    }
    return armed;
}
static void Flush() {
    for (auto& event : g_events) {
        if (event.flushed || !event.ready.load(std::memory_order_acquire)) continue;
        wchar_t suffix[96]{};
        bool ok = true;
        swprintf_s(suffix, L"provider-%lu-%02u.ctx", GetCurrentProcessId(), event.sequence);
        ok = Save(suffix, &event.context, sizeof(event.context)) && ok;
        swprintf_s(suffix, L"provider-%lu-%02u.stack", GetCurrentProcessId(), event.sequence);
        ok = Save(suffix, event.stack, (DWORD)event.stackBytes) && ok;
        swprintf_s(suffix, L"provider-%lu-%02u.code", GetCurrentProcessId(), event.sequence);
        ok = Save(suffix, event.code, (DWORD)event.codeBytes) && ok;
        char metadata[1536]{}, reference[49]{};
        for (unsigned i = 0; i < 24; ++i) sprintf_s(reference + i*2, 3, "%02x", event.reference[i]);
        int size = sprintf_s(metadata,
            "version=1\npid=%lu\ntid=%lu\nsequence=%u\nstage=%u\ntick=%llu\nimage_base=0x%llx\n"
            "address=0x%llx\nvalue=0x%llx\nvalue_bytes=%llu\nreference=%s\nreference_bytes=%llu\n"
            "rip=0x%llx\nrsp=0x%llx\ncode_address=0x%llx\ncode_bytes=%llu\nstack_bytes=%llu\n"
            "limitation=Post-instruction, sequential copies; stack is not an authenticated unwind.\n",
            GetCurrentProcessId(), event.tid, event.sequence, event.stage, event.tick,
            (unsigned long long)g_base, (unsigned long long)event.address, event.value,
            (unsigned long long)event.valueBytes, reference, (unsigned long long)event.referenceBytes,
            event.context.Rip, event.context.Rsp, (unsigned long long)event.codeAddress,
            (unsigned long long)event.codeBytes, (unsigned long long)event.stackBytes);
        swprintf_s(suffix, L"provider-%lu-%02u.txt", GetCurrentProcessId(), event.sequence);
        ok = size > 0 && Save(suffix, metadata, (DWORD)size) && ok;
        event.flushed = true;
        if (!ok) g_outputFailures.fetch_add(1);
        LogMsg("[ProviderWatch] sample=%u stage=%u tid=%lu address=%p value=0x%llx rip=%p saved=%u",
               event.sequence, event.stage, event.tid, (void*)event.address, event.value,
               (void*)event.context.Rip, ok ? 1 : 0);
    }
}
static bool PinExecutable() {
    wchar_t path[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH) ||
        _wcsicmp(path, L"D:\\Marathon-live\\Marathon.exe") != 0 || IsDebuggerPresent()) return false;
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    HCRYPTPROV provider = 0; HCRYPTHASH hash = 0;
    bool ok = CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) &&
              CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash);
    unsigned char buffer[32768]; DWORD got = 0;
    while (ok) {
        if (!ReadFile(file, buffer, sizeof(buffer), &got, nullptr)) { ok = false; break; }
        if (!got) break;
        ok = CryptHashData(hash, buffer, got, 0) != FALSE;
    }
    unsigned char digest[32]{}; DWORD size = sizeof(digest);
    ok = ok && CryptGetHashParam(hash, HP_HASHVAL, digest, &size, 0) && size == sizeof(digest) &&
         memcmp(digest, kExecutableHash, sizeof(digest)) == 0;
    if (hash) CryptDestroyHash(hash);
    if (provider) CryptReleaseContext(provider, 0);
    CloseHandle(file);
    return ok;
}
static bool ParseControl(const char* text, size_t length, DWORD pid, uintptr_t base,
                         const unsigned char* currentReference, Control* result) {
    unsigned requestedPid = 0; unsigned long long requestedBase = 0, object = 0;
    char reference[49]{}; int consumed = 0;
    if (!length || length >= 512 || memchr(text, '\0', length)) return false;
    if (sscanf(text, "provider-state-watch-v1\npid %u\nbase %llx\nobject %llx\nrecord %48s %n",
               &requestedPid, &requestedBase, &object, reference, &consumed) != 4 ||
        consumed != (int)length || requestedPid != pid || requestedBase != base ||
        object < 0x10000 || object >= 0x0000800000000000ull - 0xc0 || (object & 15) ||
        strlen(reference) != 48) return false;
    Control parsed{}; parsed.object = (uintptr_t)object;
    for (unsigned i = 0; i < 24; ++i) {
        auto digit = [](char c)->int { return c >= '0' && c <= '9' ? c-'0' :
            c >= 'a' && c <= 'f' ? c-'a'+10 : c >= 'A' && c <= 'F' ? c-'A'+10 : -1; };
        const int high = digit(reference[i*2]), low = digit(reference[i*2+1]);
        if (high < 0 || low < 0) return false;
        parsed.reference[i] = (unsigned char)((high << 4) | low);
    }
    if (memcmp(parsed.reference, currentReference, 24)) return false;
    *result = parsed; return true;
}
static bool ValidateObject(const Control& control) {
    MEMORY_BASIC_INFORMATION info{};
    if (!VirtualQuery((void*)control.object, &info, sizeof(info)) || info.State != MEM_COMMIT ||
        info.Type != MEM_PRIVATE || (info.Protect & (PAGE_NOACCESS | PAGE_GUARD)) ||
        control.object + 0xc0 > (uintptr_t)info.BaseAddress + info.RegionSize) return false;
    DWORD state = 0, flag = 0, appId = 0;
    return Read(control.object + 0xc, &state, 4) && state == 1 &&
           Read(control.object + 0xbc, &flag, 4) && flag == 2 &&
           Read(control.object + 0x78, &appId, 4) && appId == 3065800;
}
static bool LoadControl(Control* result) {
    wchar_t suffix[80]{}, path[MAX_PATH]{};
    swprintf_s(suffix, L"state-target-%lu.txt", GetCurrentProcessId());
    if (!Path(path, suffix)) return false;
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    char text[512]{}; DWORD size = 0;
    bool ok = ReadFile(file, text, sizeof(text)-1, &size, nullptr) != FALSE;
    DWORD extra = 0; char byte = 0;
    ok = ok && ReadFile(file, &byte, 1, &extra, nullptr) && !extra;
    CloseHandle(file);
    unsigned char current[24]{};
    ok = ok && Read(g_base + kReferenceRva, current, sizeof(current)) &&
         ParseControl(text, size, GetCurrentProcessId(), g_base, current, result) && ValidateObject(*result);
    return ok;
}
static DWORD WINAPI Worker(void*) {
    const DWORD pid = GetCurrentProcessId();
    const char* reason = "validation_failed";
    unsigned remaining = 0;
    if (PinExecutable()) {
        g_base = (uintptr_t)GetModuleHandleW(nullptr);
        g_handler = AddVectoredExceptionHandler(1, Observe);
        if (g_handler) {
            Control target{}; bool stateMode = false, identityVerified = false;
            const ULONGLONG deadline = GetTickCount64() + kRunMs;
            ULONGLONG stateDeadline = deadline, nextScan = 0;
            unsigned previousArmed = ~0u, previousStage = 0;
            char start[512]{};
            int size = sprintf_s(start, "version=1\npid=%lu\nimage_base=0x%llx\nreference_rva=0x%llx\n"
                "max_ms=%lu\nmax_events=%u\nstate_window_ms=%lu\n", pid, (unsigned long long)g_base,
                (unsigned long long)kReferenceRva, kRunMs, kEvents, kStateMs);
            wchar_t name[80]{}; swprintf_s(name, L"provider-%lu-started.txt", pid);
            if (size > 0) Save(name, start, (DWORD)size);
            LogMsg("[ProviderWatch] started pid=%lu base=%p reference=%p max_ms=%lu max_events=%u",
                   pid, (void*)g_base, (void*)(g_base+kReferenceRva), kRunMs, kEvents);
            reason = "deadline";
            while (GetTickCount64() < deadline) {
                if (Exists(L"STOP_PROVIDER_WATCH")) { reason = "stop_requested"; break; }
                if (IsDebuggerPresent()) { reason = "debugger_detected"; break; }
                if (!stateMode && g_autoObject.load(std::memory_order_acquire)) {
                    target = g_autoControl;
                    stateMode = true; stateDeadline = g_autoTick + kStateMs; nextScan = 0;
                    char binding[256]{};
                    int bindingSize = sprintf_s(binding, "version=2\nmode=publication-handoff\npid=%lu\n"
                        "object=0x%llx\nstate_field=0x%llx\npublication_return_rva=0x%llx\n", pid,
                        (unsigned long long)target.object, (unsigned long long)(target.object+0xc),
                        (unsigned long long)kPublicationReturnRva);
                    wchar_t bindingName[80]{}; swprintf_s(bindingName, L"provider-%lu-bound.txt", pid);
                    if (bindingSize <= 0 || !Save(bindingName, binding, (DWORD)bindingSize)) g_outputFailures.fetch_add(1);
                    LogMsg("[ProviderWatch] automatic_state_target object=%p field=%p identity=pinned_publication_registers",
                           (void*)target.object, (void*)(target.object+0xc));
                }
                if (stateMode) {
                    unsigned char current[24]{};
                    if (!Read(g_base+kReferenceRva, current, 24) || memcmp(current, target.reference, 24)) {
                        reason = "reference_changed"; break;
                    }
                    if (!identityVerified) {
                        DWORD appId = 0, flag = 0, state = 0;
                        if (Read(target.object+0x78, &appId, 4) && appId == 3065800 &&
                            Read(target.object+0xbc, &flag, 4) && Read(target.object+0xc, &state, 4)) {
                            identityVerified = true;
                            LogMsg("[ProviderWatch] identity_verified appid=%lu flag=%lu state=%lu", appId, flag, state);
                        }
                    }
                    if (GetTickCount64() >= stateDeadline) { reason = "state_window_complete"; break; }
                    if (g_counts[2].load() >= kEventsPerStage) { reason = "state_event_limit"; break; }
                }
                if (GetTickCount64() >= nextScan) {
                    const unsigned stage = stateMode ? 2 : 1;
                    const uintptr_t address = g_counts[stage].load() < kEventsPerStage ?
                        (stateMode ? target.object+0xc : g_base+kReferenceRva) : 0;
                    const unsigned armed = Scan(address, stage);
                    if (armed != previousArmed || stage != previousStage) {
                        LogMsg("[ProviderWatch] stage=%u armed_threads=%u address=%p partial_thread_coverage=1",
                               stage, armed, (void*)address);
                        previousArmed = armed; previousStage = stage;
                    }
                    nextScan = GetTickCount64() + 250;
                }
                Flush(); Sleep(20);
            }
        }
    }
    g_stopping.store(true, std::memory_order_release);
    Scan(0, 0); Flush();
    for (auto& row : g_rows) if (row.owned.load()) ++remaining;
    if (!remaining && g_handler) { RemoveVectoredExceptionHandler(g_handler); g_handler = nullptr; }
    // If a context could not be restored, retain the VEH so that its next owned
    // trap self-restores. The controlled-run launcher ends the client regardless.
    char end[512]{};
    const unsigned publicationHits = g_counts[1].load(), stateHits = g_counts[2].load();
    int size = sprintf_s(end, "version=1\npid=%lu\nreason=%s\npublication_events=%u\nstate_events=%u\n"
        "publication_hits=%u\nstate_hits=%u\ndeferred_restore_threads=%u\noutput_failures=%u\n", pid, reason,
        publicationHits < kEventsPerStage ? publicationHits : kEventsPerStage,
        stateHits < kEventsPerStage ? stateHits : kEventsPerStage,
        publicationHits, stateHits, remaining, g_outputFailures.load());
    wchar_t name[80]{}; swprintf_s(name, L"provider-%lu-ended.txt", pid);
    if (size > 0) Save(name, end, (DWORD)size);
    LogMsg("[ProviderWatch] ended reason=%s publication_events=%u state_events=%u deferred_restore_threads=%u",
           reason, g_counts[1].load(), g_counts[2].load(), remaining);
    for (auto& row : g_rows) if (row.thread) { CloseHandle(row.thread); row.thread = nullptr; }
    return remaining ? 2 : 0;
}
static void Install() {
    if (g_started.exchange(true)) return;
    const DWORD length = GetEnvironmentVariableW(L"MARATHON_PROVIDER_WATCH_DIR", g_directory, MAX_PATH);
    if (!length || length > MAX_PATH-90 || !Exists(L"ARM_PROVIDER_WATCH")) return;
    HANDLE worker = CreateThread(nullptr, 0, Worker, nullptr, 0, nullptr);
    if (worker) CloseHandle(worker);
}
} // namespace provider_watch
