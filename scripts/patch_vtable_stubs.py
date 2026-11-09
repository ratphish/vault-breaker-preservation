import re

path = r'D:\vault-breaker-preservation\client_proxy\steam_api64.cpp'
with open(path, 'r', encoding='utf-8') as f:
    code = f.read()

# 1. Add UserStub definitions before InitInterfaceTables
user_stub_code = """
template<int N>
static int64_t UserStub(void* self, ...) {
    void* caller = _ReturnAddress();
    LogMsg("[SteamUser-STUB] Slot %d called! (self=%p, caller=%p)", N, self, caller);
    return 0;
}

#define STUB_ROW_8(base) \\
    (void*)UserStub<base+0>, (void*)UserStub<base+1>, (void*)UserStub<base+2>, (void*)UserStub<base+3>, \\
    (void*)UserStub<base+4>, (void*)UserStub<base+5>, (void*)UserStub<base+6>, (void*)UserStub<base+7>

static void* g_user_default_stubs[64] = {
    STUB_ROW_8(0),
    STUB_ROW_8(8),
    STUB_ROW_8(16),
    STUB_ROW_8(24),
    STUB_ROW_8(32),
    STUB_ROW_8(40),
    STUB_ROW_8(48),
    STUB_ROW_8(56)
};

static uint32_t SteamUser_GetAuthTicketForWebApi(void* self, const char* pchIdentity) {
    LogMsg("[SteamUser] GetAuthTicketForWebApi(self=%p, identity='%s') called -> ticket 1",
           self, pchIdentity ? pchIdentity : "NULL");
    return 1;
}

static int SteamUser_UserHasLicenseForApp(void* self, uint64_t steamID, uint32_t appID) {
    LogMsg("[SteamUser] UserHasLicenseForApp(self=%p, steamID=%llu, appID=%u) called -> 0 (HasLicense)",
           self, steamID, appID);
    return 0; // k_EUserHasLicenseResultHasLicense = 0
}
"""

# Place it right before static void InitInterfaceTables()
target_init = "static void InitInterfaceTables() {"
assert target_init in code, "InitInterfaceTables not found"
code = code.replace(target_init, user_stub_code + "\n" + target_init, 1)

# In InitInterfaceTables, replace `for (int i = 0; i < 64; i++) g_user_vtable[i] = (void*)MethodReturnZero;`
old_user_init = "for (int i = 0; i < 64; i++) g_user_vtable[i] = (void*)MethodReturnZero;"
new_user_init = "for (int i = 0; i < 64; i++) g_user_vtable[i] = g_user_default_stubs[i];"
assert old_user_init in code, "old_user_init not found"
code = code.replace(old_user_init, new_user_init, 1)

# Add slot 14 and slot 18 mapping
old_mappings = """    g_user_vtable[0] = (void*)SteamUser_GetHSteamUser;
    g_user_vtable[1] = (void*)SteamUser_BLoggedOn;
    g_user_vtable[2] = (void*)SteamUser_GetSteamID;
    g_user_vtable[13] = (void*)SteamUser_GetAuthSessionTicket;
    g_user_vtable[17] = (void*)SteamUser_CancelAuthTicket;"""

new_mappings = """    g_user_vtable[0] = (void*)SteamUser_GetHSteamUser;
    g_user_vtable[1] = (void*)SteamUser_BLoggedOn;
    g_user_vtable[2] = (void*)SteamUser_GetSteamID;
    g_user_vtable[13] = (void*)SteamUser_GetAuthSessionTicket;
    g_user_vtable[14] = (void*)SteamUser_GetAuthTicketForWebApi;
    g_user_vtable[17] = (void*)SteamUser_CancelAuthTicket;
    g_user_vtable[18] = (void*)SteamUser_UserHasLicenseForApp;"""

assert old_mappings in code, "old_mappings not found"
code = code.replace(old_mappings, new_mappings, 1)

with open(path, 'w', encoding='utf-8', newline='\r\n') as f:
    f.write(code)

print("[+] Successfully patched steam_api64.cpp with vtable stub instrumentation!")
