import os

filepath = r'D:\vault-breaker-preservation\client_proxy\steam_api64.cpp'
with open(filepath, 'r', encoding='utf-8') as f:
    code = f.read()

# 1. Add LogCallerInfo right after LogMsg if not present
caller_info_code = '''static void LogCallerInfo(const char* prefix, void* caller) {
    DWORD tid = GetCurrentThreadId();
    HMODULE hMod = NULL;
    char modName[MAX_PATH] = "Unknown";
    uintptr_t rva = 0;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)caller, &hMod) && hMod) {
        char fullPath[MAX_PATH];
        if (GetModuleFileNameA(hMod, fullPath, sizeof(fullPath))) {
            const char* slash = strrchr(fullPath, '\\\\');
            strncpy(modName, slash ? slash + 1 : fullPath, sizeof(modName) - 1);
        }
        rva = (uintptr_t)caller - (uintptr_t)hMod;
    }
    LogMsg("[%s] [TID:%u] from %s+0x%llX (addr=%p)", prefix, tid, modName, (unsigned long long)rva, caller);
}
'''
if 'static void LogCallerInfo' not in code:
    idx = code.find('static bool CaseInsensitiveContains')
    assert idx != -1
    code = code[:idx] + caller_info_code + '\n' + code[idx:]

# 2. Update SteamUser_BLoggedOn
old_logged_on = '''static int SteamUser_BLoggedOn(void* self) { 
    LogMsg("[SteamUser] BLoggedOn called -> 1");
    return 1; 
}'''
new_logged_on = '''static int SteamUser_BLoggedOn(void* self) { 
    void* caller = _ReturnAddress();
    LogCallerInfo("SteamUser-BLoggedOn", caller);
    LogMsg("[SteamUser] BLoggedOn called -> 1");
    return 1; 
}'''
assert old_logged_on in code, "old_logged_on not found"
code = code.replace(old_logged_on, new_logged_on)

# 3. Update SteamApps_BIsSubscribed
old_subscribed = '''static int SteamApps_BIsSubscribed(void* self) { 
    LogMsg("[SteamApps] BIsSubscribed called -> 1");
    return 1; 
}'''
new_subscribed = '''static int SteamApps_BIsSubscribed(void* self) { 
    void* caller = _ReturnAddress();
    LogCallerInfo("SteamApps-BIsSubscribed", caller);
    LogMsg("[SteamApps] BIsSubscribed called -> 1");
    return 1; 
}'''
assert old_subscribed in code, "old_subscribed not found"
code = code.replace(old_subscribed, new_subscribed)

# 4. Update SteamApps_BIsSubscribedApp
old_sub_app = '''static int SteamApps_BIsSubscribedApp(void* self, uint32_t nAppID) { 
    LogMsg("[SteamApps] BIsSubscribedApp(%u) called -> 1", nAppID);
    return 1; 
}'''
new_sub_app = '''static int SteamApps_BIsSubscribedApp(void* self, uint32_t nAppID) { 
    void* caller = _ReturnAddress();
    LogCallerInfo("SteamApps-BIsSubscribedApp", caller);
    LogMsg("[SteamApps] BIsSubscribedApp(%u) called -> 1", nAppID);
    return 1; 
}'''
assert old_sub_app in code, "old_sub_app not found"
code = code.replace(old_sub_app, new_sub_app)

# 5. Update SteamAPI_IsSteamRunning
old_running = '''__declspec(dllexport) bool __cdecl SteamAPI_IsSteamRunning() {
    return true;
}'''
new_running = '''__declspec(dllexport) bool __cdecl SteamAPI_IsSteamRunning() {
    void* caller = _ReturnAddress();
    LogCallerInfo("SteamAPI-IsSteamRunning", caller);
    LogMsg("[SteamAPI] SteamAPI_IsSteamRunning called -> true");
    return true;
}'''
assert old_running in code, "old_running not found"
code = code.replace(old_running, new_running)

# 6. Update SteamUser_RequestEncryptedAppTicket
old_req_ticket = '''static uint64_t g_next_api_call = 1;
static uint64_t SteamUser_RequestEncryptedAppTicket(void* self, void* pDataToInclude, int cbDataToInclude) {
    uint64_t callId = g_next_api_call++;
    LogMsg("[SteamUser] RequestEncryptedAppTicket called -> handle %llu", callId);
    return callId;
}'''
new_req_ticket = '''static uint64_t g_next_api_call = 1;
static uint64_t SteamUser_RequestEncryptedAppTicket(void* self, void* pDataToInclude, int cbDataToInclude) {
    void* caller = _ReturnAddress();
    LogCallerInfo("SteamUser-RequestEncryptedAppTicket", caller);
    uint64_t callId = g_next_api_call++;
    LogMsg("[SteamUser] RequestEncryptedAppTicket called (pDataToInclude=%p, cb=%d) -> handle %llu",
           pDataToInclude, cbDataToInclude, (unsigned long long)callId);
    return callId;
}'''
assert old_req_ticket in code, "old_req_ticket not found"
code = code.replace(old_req_ticket, new_req_ticket)

# 7. Update SteamUser_GetEncryptedAppTicket
old_get_ticket = '''static int SteamUser_GetEncryptedAppTicket(void* self, void* pTicket, int cbMaxTicket, uint32_t* pcbTicket) {
    LogMsg("[SteamUser] GetEncryptedAppTicket called (max: %d)", cbMaxTicket);
    if (!pTicket || cbMaxTicket <= 0) {
        if (pcbTicket) *pcbTicket = 128;
        return 0;
    }

    int len = cbMaxTicket < 128 ? cbMaxTicket : 128;
    unsigned char* ticket = (unsigned char*)pTicket;
    for (int i = 0; i < len; i++) {
        ticket[i] = (unsigned char)(0xAA ^ (i * 13));
    }

    if (pcbTicket) *pcbTicket = len;
    LogMsg("[SteamUser] Generated mock encrypted app ticket (len=%d)", len);
    return 1;
}'''
new_get_ticket = '''static int SteamUser_GetEncryptedAppTicket(void* self, void* pTicket, int cbMaxTicket, uint32_t* pcbTicket) {
    void* caller = _ReturnAddress();
    LogCallerInfo("SteamUser-GetEncryptedAppTicket", caller);
    LogMsg("[SteamUser] GetEncryptedAppTicket called (pTicket=%p, max=%d, pcbTicket=%p)", pTicket, cbMaxTicket, pcbTicket);
    if (!pTicket || cbMaxTicket <= 0) {
        if (pcbTicket) *pcbTicket = 128;
        return 0;
    }

    int len = cbMaxTicket < 128 ? cbMaxTicket : 128;
    unsigned char* ticket = (unsigned char*)pTicket;
    for (int i = 0; i < len; i++) {
        ticket[i] = (unsigned char)(0xAA ^ (i * 13));
    }

    if (pcbTicket) *pcbTicket = len;
    LogMsg("[SteamUser] Generated mock encrypted app ticket (len=%d) -> returning 1 (true)", len);
    return 1;
}'''
assert old_get_ticket in code, "old_get_ticket not found"
code = code.replace(old_get_ticket, new_get_ticket)

# 8. Update Hook_CertVerifyCertificateChainPolicy
old_cert = '''    LogMsg("[Crypto] CertVerifyCertificateChainPolicy called (policy=%p, caller=%p, subject='%s', issuer='%s')",
           pszPolicyOID, caller, certSubject, certIssuer);
    void* stack[16];
    USHORT frames = RtlCaptureStackBackTrace(0, 16, stack, NULL);
    for (USHORT f = 0; f < frames; f++) {
        LogMsg("[Crypto-Stack]   #%d: %p", f, stack[f]);
    }

    BOOL res = TRUE;
    if (g_real_CertVerifyCertificateChainPolicy) {
        res = g_real_CertVerifyCertificateChainPolicy(pszPolicyOID, pChainContext, pPolicyPara, pPolicyStatus);
    }

    if (pszPolicyOID == (LPCSTR)1 || (intptr_t)pszPolicyOID == 1) {
        if (pPolicyStatus) {
            pPolicyStatus->dwError = 0; // CERT_TRUST_NO_ERROR = 0
        }

        LogMsg("[Crypto] CertVerifyCertificateChainPolicy (SSL) -> Forcing SUCCESS");
    }

    return TRUE;'''

new_cert = '''    const char* policyDesc = "UNKNOWN";
    if (pszPolicyOID == (LPCSTR)1 || (intptr_t)pszPolicyOID == 1) policyDesc = "BASE (1)";
    else if (pszPolicyOID == (LPCSTR)2 || (intptr_t)pszPolicyOID == 2) policyDesc = "AUTHENTICODE (2)";
    else if (pszPolicyOID == (LPCSTR)3 || (intptr_t)pszPolicyOID == 3) policyDesc = "NT_AUTH (3)";
    else if (pszPolicyOID == (LPCSTR)4 || (intptr_t)pszPolicyOID == 4) policyDesc = "SSL (4)";
    else if ((uintptr_t)pszPolicyOID > 0xFFFF) policyDesc = pszPolicyOID;

    LogMsg("[Crypto] CertVerifyCertificateChainPolicy called (policy=%s, subject='%s', issuer='%s')",
           policyDesc, certSubject, certIssuer);
    LogCallerInfo("Crypto-Caller", caller);

    void* stack[8];
    USHORT frames = RtlCaptureStackBackTrace(0, 8, stack, NULL);
    for (USHORT f = 0; f < frames; f++) {
        LogCallerInfo("Crypto-Stack", stack[f]);
    }

    BOOL res = TRUE;
    if (g_real_CertVerifyCertificateChainPolicy) {
        res = g_real_CertVerifyCertificateChainPolicy(pszPolicyOID, pChainContext, pPolicyPara, pPolicyStatus);
    }
    if (pPolicyStatus) {
        pPolicyStatus->dwError = 0; // CERT_TRUST_NO_ERROR = 0
    }
    LogMsg("[Crypto] CertVerifyCertificateChainPolicy (%s) -> Forcing SUCCESS", policyDesc);
    return TRUE;'''
assert old_cert in code, "old_cert not found"
code = code.replace(old_cert, new_cert)

with open(filepath, 'w', encoding='utf-8') as f:
    f.write(code)
print('Successfully applied all instrumentation and crypto fixes!')
