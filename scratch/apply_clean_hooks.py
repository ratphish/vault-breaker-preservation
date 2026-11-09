with open(r"D:\vault-breaker-preservation\client_proxy\steam_api64.cpp", "r", encoding="utf-8") as f:
    text = f.read()

# 1. Add winhttp header and lib
if "#include <winhttp.h>" not in text:
    text = text.replace(
        "#include <wincrypt.h>",
        "#include <wincrypt.h>\n#include <winhttp.h>"
    )
if 'winhttp.lib' not in text:
    text = text.replace(
        '#pragma comment(lib, "crypt32.lib")',
        '#pragma comment(lib, "crypt32.lib")\n#pragma comment(lib, "winhttp.lib")'
    )

# 2. Update Hook_CertVerifyCertificateChainPolicy to only touch SSL policy (1)
old_cert = '''static BOOL WINAPI Hook_CertVerifyCertificateChainPolicy(
    LPCSTR pszPolicyOID,
    PCCERT_CHAIN_CONTEXT pChainContext,
    PCERT_CHAIN_POLICY_PARA pPolicyPara,
    PCERT_CHAIN_POLICY_STATUS pPolicyStatus
) {
    LogMsg("[Crypto] CertVerifyCertificateChainPolicy called (policy=%p) -> Forcing SUCCESS", pszPolicyOID);
    if (pPolicyStatus) {
        pPolicyStatus->dwError = 0; // CERT_TRUST_NO_ERROR = 0
    }
    return TRUE;
}'''

new_cert = '''static BOOL WINAPI Hook_CertVerifyCertificateChainPolicy(
    LPCSTR pszPolicyOID,
    PCCERT_CHAIN_CONTEXT pChainContext,
    PCERT_CHAIN_POLICY_PARA pPolicyPara,
    PCERT_CHAIN_POLICY_STATUS pPolicyStatus
) {
    LogMsg("[Crypto] CertVerifyCertificateChainPolicy called (policy=%p)", pszPolicyOID);
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
    return TRUE;
}'''
text = text.replace(old_cert, new_cert)

# 3. Update Hook_getaddrinfo to only redirect Bungie domains
old_gai = '''    if (pNodeName && strcmp(pNodeName, "127.0.0.1") != 0 && strcmp(pNodeName, "localhost") != 0) {
        LogMsg("[Egress] Intercepted DNS getaddrinfo for '%s' -> Redirecting to '%s:%s'",
               pNodeName, g_server_ip, g_server_port);
        node = g_server_ip;
        if (pServiceName && (strcmp(pServiceName, "443") == 0 || strcmp(pServiceName, "https") == 0)) {
            service = g_server_port;
        }
    }'''

new_gai = '''    if (pNodeName && (strstr(pNodeName, "deadorbit") || strstr(pNodeName, "bungie") || strstr(pNodeName, "goliath") || strstr(pNodeName, "marathon") || strstr(pNodeName, "playfab"))) {
        LogMsg("[Egress] Intercepted DNS getaddrinfo for '%s' -> Redirecting to '%s:%s'",
               pNodeName, g_server_ip, g_server_port);
        node = g_server_ip;
        if (pServiceName && (strcmp(pServiceName, "443") == 0 || strcmp(pServiceName, "https") == 0)) {
            service = g_server_port;
        }
    }'''
text = text.replace(old_gai, new_gai)

# 4. Update Hook_GetAddrInfoW to only redirect Bungie domains
old_gaiw = '''        if (strcmp(nodeA, "127.0.0.1") != 0 && strcmp(nodeA, "localhost") != 0) {
            LogMsg("[Egress] Intercepted DNS GetAddrInfoW for '%s' -> Redirecting to '%s'", nodeA, g_server_ip);
            wchar_t wServerIp[64] = L"127.0.0.1";
            return g_real_GetAddrInfoW ? g_real_GetAddrInfoW(wServerIp, pServiceName, pHints, ppResult) : WSAEFAULT;
        }'''

new_gaiw = '''        if (strstr(nodeA, "deadorbit") || strstr(nodeA, "bungie") || strstr(nodeA, "goliath") || strstr(nodeA, "marathon") || strstr(nodeA, "playfab")) {
            LogMsg("[Egress] Intercepted DNS GetAddrInfoW for '%s' -> Redirecting to '%s'", nodeA, g_server_ip);
            wchar_t wServerIp[64] = L"127.0.0.1";
            return g_real_GetAddrInfoW ? g_real_GetAddrInfoW(wServerIp, pServiceName, pHints, ppResult) : WSAEFAULT;
        }'''
text = text.replace(old_gaiw, new_gaiw)

# 5. Update Hook_gethostbyname to preserve local PC hostname
old_ghbn = '''    if (name && strcmp(name, "127.0.0.1") != 0 && strcmp(name, "localhost") != 0) {
        LogMsg("[Egress] Intercepted DNS gethostbyname for '%s' -> Redirecting to '%s'",
               name, g_server_ip);
        return g_real_gethostbyname ? g_real_gethostbyname(g_server_ip) : NULL;
    }'''

new_ghbn = '''    if (name && (strstr(name, "deadorbit") || strstr(name, "bungie") || strstr(name, "goliath") || strstr(name, "marathon") || strstr(name, "playfab"))) {
        LogMsg("[Egress] Intercepted DNS gethostbyname for '%s' -> Redirecting to '%s'",
               name, g_server_ip);
        return g_real_gethostbyname ? g_real_gethostbyname(g_server_ip) : NULL;
    }'''
text = text.replace(old_ghbn, new_ghbn)

# 6. Add WinHTTP function hooks
winhttp_hooks = '''typedef HINTERNET (WINAPI *WinHttpConnect_t)(
    HINTERNET hSession,
    LPCWSTR pswzServerName,
    INTERNET_PORT nServerPort,
    DWORD dwReserved
);
static WinHttpConnect_t g_real_WinHttpConnect = NULL;

static HINTERNET WINAPI Hook_WinHttpConnect(
    HINTERNET hSession,
    LPCWSTR pswzServerName,
    INTERNET_PORT nServerPort,
    DWORD dwReserved
) {
    if (pswzServerName) {
        char sNameA[256] = { 0 };
        WideCharToMultiByte(CP_UTF8, 0, pswzServerName, -1, sNameA, sizeof(sNameA), NULL, NULL);
        LogMsg("[WinHTTP] WinHttpConnect(server='%s', port=%u)", sNameA, (unsigned int)nServerPort);
        if (strstr(sNameA, "deadorbit") || strstr(sNameA, "bungie") || strstr(sNameA, "goliath") || strstr(sNameA, "playfab") || (strcmp(sNameA, "127.0.0.1") != 0 && strcmp(sNameA, "localhost") != 0)) {
            uint16_t target_port = (uint16_t)atoi(g_server_port);
            LogMsg("[Egress] Redirecting WinHttpConnect from '%s:%u' to 127.0.0.1:%u", sNameA, (unsigned int)nServerPort, target_port);
            return g_real_WinHttpConnect ? g_real_WinHttpConnect(hSession, L"127.0.0.1", (INTERNET_PORT)target_port, dwReserved) : NULL;
        }
    }
    return g_real_WinHttpConnect ? g_real_WinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved) : NULL;
}

typedef HINTERNET (WINAPI *WinHttpOpenRequest_t)(
    HINTERNET hConnect,
    LPCWSTR pwszVerb,
    LPCWSTR pwszObjectName,
    LPCWSTR pwszVersion,
    LPCWSTR pwszReferrer,
    LPCWSTR *ppwszAcceptTypes,
    DWORD dwFlags
);
static WinHttpOpenRequest_t g_real_WinHttpOpenRequest = NULL;

static HINTERNET WINAPI Hook_WinHttpOpenRequest(
    HINTERNET hConnect,
    LPCWSTR pwszVerb,
    LPCWSTR pwszObjectName,
    LPCWSTR pwszVersion,
    LPCWSTR pwszReferrer,
    LPCWSTR *ppwszAcceptTypes,
    DWORD dwFlags
) {
    char objA[256] = { 0 };
    if (pwszObjectName) WideCharToMultiByte(CP_UTF8, 0, pwszObjectName, -1, objA, sizeof(objA), NULL, NULL);
    LogMsg("[WinHTTP] WinHttpOpenRequest(object='%s', flags=0x%lx)", objA, dwFlags);

    HINTERNET hReq = g_real_WinHttpOpenRequest ?
        g_real_WinHttpOpenRequest(hConnect, pwszVerb, pwszObjectName, pwszVersion, pwszReferrer, ppwszAcceptTypes, dwFlags) : NULL;

    if (hReq) {
        DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                         SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                         SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                         SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
        LogMsg("[WinHTTP] Applied SECURITY_FLAG_IGNORE_UNKNOWN_CA to request %p", hReq);
    }
    return hReq;
}
'''

if "Hook_WinHttpConnect" not in text:
    text = text.replace("// ---------------------------------------------------------------------------\n// VFS & File Logging Hooks", winhttp_hooks + "\n// ---------------------------------------------------------------------------\n// VFS & File Logging Hooks")

# 7. Update HookModuleIAT to include WinHTTP
old_iat_check = '''        bool isWs2 = (_stricmp(modName, "WS2_32.dll") == 0);
        bool isK32 = (_stricmp(modName, "KERNEL32.dll") == 0);
        bool isCrypt = (_stricmp(modName, "CRYPT32.dll") == 0);

        if (isWs2 || isK32 || isCrypt) {'''

new_iat_check = '''        bool isWs2 = (_stricmp(modName, "WS2_32.dll") == 0);
        bool isK32 = (_stricmp(modName, "KERNEL32.dll") == 0);
        bool isCrypt = (_stricmp(modName, "CRYPT32.dll") == 0);
        bool isWinHttp = (_stricmp(modName, "WINHTTP.dll") == 0);

        if (isWs2 || isK32 || isCrypt || isWinHttp) {'''
text = text.replace(old_iat_check, new_iat_check)

# 8. Add isWinHttp handling in thunk loop
old_k32_check = '''                } else if (isK32) {
                    if (!(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                        PIMAGE_IMPORT_BY_NAME impName = (PIMAGE_IMPORT_BY_NAME)((uint8_t*)hMod + origThunk->u1.AddressOfData);
                        const char* name = (const char*)impName->Name;
                        if (strcmp(name, "CreateFileW") == 0) { hook = (void*)Hook_CreateFileW; hookName = "CreateFileW"; }
                        else if (strcmp(name, "CreateFileA") == 0) { hook = (void*)Hook_CreateFileA; hookName = "CreateFileA"; }
                    }
                }'''

new_k32_check = '''                } else if (isK32) {
                    if (!(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                        PIMAGE_IMPORT_BY_NAME impName = (PIMAGE_IMPORT_BY_NAME)((uint8_t*)hMod + origThunk->u1.AddressOfData);
                        const char* name = (const char*)impName->Name;
                        if (strcmp(name, "CreateFileW") == 0) { hook = (void*)Hook_CreateFileW; hookName = "CreateFileW"; }
                        else if (strcmp(name, "CreateFileA") == 0) { hook = (void*)Hook_CreateFileA; hookName = "CreateFileA"; }
                    }
                } else if (isWinHttp) {
                    if (!(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                        PIMAGE_IMPORT_BY_NAME impName = (PIMAGE_IMPORT_BY_NAME)((uint8_t*)hMod + origThunk->u1.AddressOfData);
                        const char* name = (const char*)impName->Name;
                        if (strcmp(name, "WinHttpConnect") == 0) { hook = (void*)Hook_WinHttpConnect; hookName = "WinHttpConnect"; }
                        else if (strcmp(name, "WinHttpOpenRequest") == 0) { hook = (void*)Hook_WinHttpOpenRequest; hookName = "WinHttpOpenRequest"; }
                    }
                }'''
text = text.replace(old_k32_check, new_k32_check)

# 9. Update InstallIATHooks to resolve WinHTTP exports
old_init_iat = '''    HMODULE hCrypt = GetModuleHandleA("CRYPT32.dll");
    if (!hCrypt) hCrypt = LoadLibraryA("CRYPT32.dll");
    if (hCrypt) {
        g_real_CertVerifyCertificateChainPolicy = (CertVerifyCertificateChainPolicy_t)GetProcAddress(hCrypt, "CertVerifyCertificateChainPolicy");
    }'''

new_init_iat = '''    HMODULE hCrypt = GetModuleHandleA("CRYPT32.dll");
    if (!hCrypt) hCrypt = LoadLibraryA("CRYPT32.dll");
    if (hCrypt) {
        g_real_CertVerifyCertificateChainPolicy = (CertVerifyCertificateChainPolicy_t)GetProcAddress(hCrypt, "CertVerifyCertificateChainPolicy");
    }

    HMODULE hWinHttp = GetModuleHandleA("WINHTTP.dll");
    if (!hWinHttp) hWinHttp = LoadLibraryA("WINHTTP.dll");
    if (hWinHttp) {
        g_real_WinHttpConnect = (WinHttpConnect_t)GetProcAddress(hWinHttp, "WinHttpConnect");
        g_real_WinHttpOpenRequest = (WinHttpOpenRequest_t)GetProcAddress(hWinHttp, "WinHttpOpenRequest");
    }'''
text = text.replace(old_init_iat, new_init_iat)

with open(r"D:\vault-breaker-preservation\client_proxy\steam_api64.cpp", "w", encoding="utf-8") as f:
    f.write(text)

print("Applied clean WinHTTP and targeted DNS hooks successfully!")
