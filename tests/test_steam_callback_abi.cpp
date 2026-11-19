// Exercise actual proxy dispatch against compiler-generated MSVC callback
// vtables. No game, production proxy DLL, external network or UI is involved.
#ifdef MARATHON_TEST_BASELINE
#include "../client_proxy/steam_api64_baseline_14D83586.cpp"
#else
#include "../client_proxy/steam_api64.cpp"
#endif

// Match the two overloaded Run declarations of the Steam callback interface.
// MSVC groups overloads in reverse declaration order in the vtable.
struct CallbackInterface {
    virtual void Run(void*) = 0;
    virtual void Run(void*, bool, uint64_t) = 0;
    virtual int GetCallbackSizeBytes() = 0;
};
struct CallbackProbe : CallbackInterface {
    unsigned regular = 0, result = 0;
    bool failed = true;
    uint64_t call = 0;
    int payload = 0;
    void Run(void* data) override { ++regular; payload = *(int*)data; }
    void Run(void* data, bool failure, uint64_t id) override {
        ++result; failed = failure; call = id; payload = *(int*)data;
    }
    int GetCallbackSizeBytes() override { return sizeof(int); }
};

int main() {
    strcpy_s(g_log_path, "NUL");
    // The maintenance pass can visit this standalone executable's imports;
    // populate real API pointers before running the production callback pump.
    InstallIATHooks();
    CallbackProbe callResult, regular, persona, avatar, join;
    SteamAPI_RegisterCallResult(&callResult, 0x123456789abcdef0ULL);
    SteamAPI_RegisterCallback(&regular, 101);
    SteamAPI_RegisterCallback(&persona, 304);
    SteamAPI_RegisterCallback(&avatar, 334);
    SteamAPI_RegisterCallback(&join, 337); // Never fabricate a join invitation.
    SteamAPI_RunCallbacks();
    SteamAPI_RunCallbacks();
    SteamAPI_RunCallbacks();
    if (callResult.result != 1 || callResult.regular != 0 || callResult.failed ||
        callResult.call != 0x123456789abcdef0ULL || callResult.payload != 1 ||
        regular.regular != 1 || regular.result != 0 || persona.regular != 1 || persona.result != 0 ||
        avatar.regular != 1 || avatar.result != 0 || join.regular != 0 || join.result != 0) {
        fprintf(stderr, "FAIL: call-result slot result=%u regular=%u id=%llx; regular slot result=%u regular=%u\n",
                callResult.result, callResult.regular, callResult.call, regular.result, regular.regular);
        return 1;
    }
    puts("PASS: MSVC callback ABI, call handle, callback IDs, no fabricated join, exactly-once dispatch");
    return 0;
}
