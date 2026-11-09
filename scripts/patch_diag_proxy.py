"""Patches client_proxy/steam_api64_diag.cpp to enhance SteamUtils stubs,
refine EncryptedAppTicket payload layout, and dump caller memory.
"""
import sys
import re

cpp_path = r"D:\vault-breaker-preservation\client_proxy\steam_api64_diag.cpp"
with open(cpp_path, "r", encoding="utf-8") as f:
    content = f.read()

# 1. Update SteamUser_GetEncryptedAppTicket
old_ticket_func_pattern = re.compile(
    r"static int SteamUser_GetEncryptedAppTicket\(void\* self, void\* pTicket, int cbMaxTicket, uint32_t\* pcbTicket\) \{.*?"
    r"    LogMsg\(\"\[SteamUser\] Generated valid EncryptedAppTicket Protobuf.*?\n    return 1;\n\}",
    re.DOTALL
)

new_ticket_func = """static int SteamUser_GetEncryptedAppTicket(void* self, void* pTicket, int cbMaxTicket, uint32_t* pcbTicket) {
    void* caller = _ReturnAddress();
    LogCallerInfo("SteamUser-GetEncryptedAppTicket", caller);
    LogMsg("[SteamUser] GetEncryptedAppTicket called (pTicket=%p, max=%d, pcbTicket=%p)", pTicket, cbMaxTicket, pcbTicket);

    // Dump caller instructions around ReturnAddress for offline inspection
    FILE* fpCaller = fopen("D:\\\\Marathon-live\\\\mem_ticket_caller.bin", "wb");
    if (fpCaller) {
        fwrite((uint8_t*)caller - 64, 1, 256, fpCaller);
        fclose(fpCaller);
        LogMsg("[SteamUser] Dumped 256 bytes around caller (%p) to mem_ticket_caller.bin", caller);
    }

    int user_len = g_saved_appticket_userdata_len;
    if (user_len <= 0) user_len = 24;

    int ownership_len = 128;
    int inner_len = ownership_len + user_len;

    if (!pTicket || cbMaxTicket <= 0) {
        if (pcbTicket) *pcbTicket = (uint32_t)(inner_len + 32);
        return 0;
    }

    uint8_t inner[512];
    memset(inner, 0, sizeof(inner));

    // Valve AppOwnershipTicket Header
    uint32_t* hdr = (uint32_t*)inner;
    hdr[0] = 32;               // Header length
    hdr[1] = 1;                // Flags / license status
    *(uint64_t*)&inner[8] = g_steam_id;  // SteamID64
    hdr[4] = g_app_id;         // AppID (3065800)
    hdr[5] = 0x7F000001;       // External IP (127.0.0.1)
    hdr[6] = (uint32_t)time(NULL);              // Creation time
    hdr[7] = (uint32_t)time(NULL) + 31536000;   // Expiration time (+1 year)

    for (int i = 32; i < ownership_len; i++) {
        inner[i] = (uint8_t)((i * 13) & 0xFF);
    }

    // Append UserData after AppOwnershipTicket (Valve SDK standard layout)
    if (g_saved_appticket_userdata_len > 0) {
        memcpy(&inner[ownership_len], g_saved_appticket_userdata, g_saved_appticket_userdata_len);
    } else {
        memset(&inner[ownership_len], 0x55, user_len);
    }

    uint32_t crc = CalculateCRC32(inner, inner_len);

    uint8_t proto[512];
    int p = 0;
    // Field 1: ticket_version_no = 1
    proto[p++] = (1 << 3) | 0;
    p += WriteVarint(&proto[p], 1);

    // Field 2: crc_encryptedticket
    proto[p++] = (2 << 3) | 0;
    p += WriteVarint(&proto[p], crc);

    // Field 3: cb_encrypteduserdata
    proto[p++] = (3 << 3) | 0;
    p += WriteVarint(&proto[p], user_len);

    // Field 4: cb_encrypted_appownershipticket
    proto[p++] = (4 << 3) | 0;
    p += WriteVarint(&proto[p], ownership_len);

    // Field 5: encrypted_ticket
    proto[p++] = (5 << 3) | 2;
    p += WriteVarint(&proto[p], inner_len);
    memcpy(&proto[p], inner, inner_len);
    p += inner_len;

    int copy_len = cbMaxTicket < p ? cbMaxTicket : p;
    memcpy(pTicket, proto, copy_len);
    if (pcbTicket) *pcbTicket = copy_len;

    LogMsg("[SteamUser] Generated valid EncryptedAppTicket Protobuf (total_len=%d, ownership_len=%d, user_data_len=%d, crc=0x%08X) -> returning 1 (true)",
           copy_len, ownership_len, user_len, crc);
    return 1;
}"""

content, count1 = old_ticket_func_pattern.subn(new_ticket_func, content, count=1)
print(f"Patched SteamUser_GetEncryptedAppTicket: {count1} match")

# 2. Update SteamUtils stubs
old_utils_pattern = re.compile(
    r"static int SteamUtils_IsAPICallCompleted\(void\* self, uint64_t hSteamAPICall, int\* pbFailed\) \{.*?"
    r"static int SteamUtils_GetAPICallResult\(void\* self, uint64_t hSteamAPICall, void\* pCallback, int cubCallback, int iCallbackExpected, int\* pbFailed\) \{.*?"
    r"return 1;\s*\}",
    re.DOTALL
)

new_utils = """static int SteamUtils_IsAPICallCompleted(void* self, uint64_t hSteamAPICall, int* pbFailed) {
    LogMsg("[SteamUtils] IsAPICallCompleted(call=%llu)", (unsigned long long)hSteamAPICall);
    if (pbFailed) *pbFailed = 0;
    return 1;
}

static int SteamUtils_GetAPICallFailureReason(void* self, uint64_t hSteamAPICall) {
    LogMsg("[SteamUtils] GetAPICallFailureReason(call=%llu)", (unsigned long long)hSteamAPICall);
    return 0; // k_ESteamAPICallFailureNone
}

static int SteamUtils_GetAPICallResult(void* self, uint64_t hSteamAPICall, void* pCallback, int cubCallback, int iCallbackExpected, int* pbFailed) {
    LogMsg("[SteamUtils] GetAPICallResult(call=%llu, pCallback=%p, cub=%d, expected=%d)",
           (unsigned long long)hSteamAPICall, pCallback, cubCallback, iCallbackExpected);
    if (pbFailed) *pbFailed = 0;
    if (pCallback && cubCallback >= 4) {
        *(int*)pCallback = 1; // k_EResultOK
    }
    return 1;
}"""

content, count2 = old_utils_pattern.subn(new_utils, content, count=1)
print(f"Patched SteamUtils stubs: {count2} match")

# 3. Update Hook_CertVerifyCertificateChainPolicy to log requested server name
old_cert_pattern = re.compile(
    r'LogMsg\("\[Crypto\] CertVerifyCertificateChainPolicy called \(policy=%s, subject=\'%s\', issuer=\'%s\'\)",\s*policyDesc, certSubject, certIssuer\);'
)

new_cert = """char reqServerName[256] = "none";
    if (pPolicyPara && pPolicyPara->pvExtraPolicyPara) {
        typedef struct {
            DWORD cbStruct;
            DWORD dwAuthType;
            DWORD fdwChecks;
            WCHAR *pwszServerName;
        } HTTP_POLICY_DATA;
        HTTP_POLICY_DATA* pHttpData = (HTTP_POLICY_DATA*)pPolicyPara->pvExtraPolicyPara;
        if (pHttpData->pwszServerName) {
            WideCharToMultiByte(CP_UTF8, 0, pHttpData->pwszServerName, -1, reqServerName, sizeof(reqServerName), NULL, NULL);
        }
    }
    LogMsg("[Crypto] CertVerifyCertificateChainPolicy called (target='%s', policy=%s, subject='%s', issuer='%s')",
           reqServerName, policyDesc, certSubject, certIssuer);"""

content, count3 = old_cert_pattern.subn(new_cert, content, count=1)
print(f"Patched Hook_CertVerifyCertificateChainPolicy: {count3} match")

if count1 == 1 and count2 == 1 and count3 == 1:
    with open(cpp_path, "w", encoding="utf-8") as f:
        f.write(content)
    print("[+] All patches applied cleanly!")
else:
    print(f"[-] Patching failed or partial: c1={count1}, c2={count2}, c3={count3}")
    sys.exit(1)
