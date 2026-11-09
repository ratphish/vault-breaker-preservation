import os

cpp_path = r"D:\vault-breaker-preservation\client_proxy\steam_api64.cpp"

with open(cpp_path, "r", encoding="utf-8") as f:
    content = f.read()

start_marker = "// ---------------------------------------------------------------------------\n// Network & Crypto Egress Hooking (WS2_32.dll, CRYPT32.dll)"
end_marker = "    CheckDynamicModules();\n}"

pos1 = content.find(start_marker)
pos2 = content.find(end_marker, pos1) + len(end_marker)

new_code = """// ---------------------------------------------------------------------------
// Inline Detour Engine (x64)
// ---------------------------------------------------------------------------
static bool InstallInlineHook(void* pTarget, void* pHook, size_t stolenLen, void** ppTrampoline) {
    if (!pTarget || !pHook || stolenLen < 14) return false;

    uint8_t* tramp = (uint8_t*)VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!tramp) return false;

    // Copy original instructions
    memcpy(tramp, pTarget, stolenLen);

    // Append 14-byte absolute jump back to (target + stolenLen)
    tramp[stolenLen + 0] = 0xFF;
    tramp[stolenLen + 1] = 0x25;
    tramp[stolenLen + 2] = 0x00;
    tramp[stolenLen + 3] = 0x00;
    tramp[stolenLen + 4] = 0x00;
    tramp[stolenLen + 5] = 0x00;
    *(uint64_t*)(&tramp[stolenLen + 6]) = (uint64_t)((uint8_t*)pTarget + stolenLen);

    *ppTrampoline = tramp;

    // Patch target function with 14-byte jump to hook
    DWORD oldProtect;
    if (!VirtualProtect(pTarget, stolenLen, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }

    uint8_t* targetBytes = (uint8_t*)pTarget;
    targetBytes[0] = 0xFF;
    targetBytes[1] = 0x25;
    targetBytes[2] = 0x00;
    targetBytes[3] = 0x00;
    targetBytes[4] = 0x00;
    targetBytes[5] = 0x00;
    *(uint64_t*)(&targetBytes[6]) = (uint64_t)pHook;

    if (stolenLen > 14) {
        memset(&targetBytes[14], 0x90, stolenLen - 14); // NOP padding
    }

    VirtualProtect(pTarget, stolenLen, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), pTarget, stolenLen);
    FlushInstructionCache(GetCurrentProcess(), tramp, stolenLen + 14);

    return true;
}

// ---------------------------------------------------------------------------
// Network & Crypto Egress Detours (WS2_32.dll, CRYPT32.dll, WINHTTP.dll)
// ---------------------------------------------------------------------------

// 1. CRYPT32 Hooks
typedef BOOL (WINAPI *CertVerifyCertificateChainPolicy_t)(
    LPCSTR pszPolicyOID,
    PCCERT_CHAIN_CONTEXT pChainContext,
    PCERT_CHAIN_POLICY_PARA pPolicyPara,
    PCERT_CHAIN_POLICY_STATUS pPolicyStatus
);
static CertVerifyCertificateChainPolicy_t g_real_CertVerifyCertificateChainPolicy = NULL;

static BOOL WINAPI Hook_CertVerifyCertificateChainPolicy(
    LPCSTR pszPolicyOID,
    PCCERT_CHAIN_CONTEXT pChainContext,
    PCERT_CHAIN_POLICY_PARA pPolicyPara,
    PCERT_CHAIN_POLICY_STATUS pPolicyStatus
) {
    LogMsg("[Crypto] CertVerifyCertificateChainPolicy called (policy=%p)", pszPolicyOID);
    if (pszPolicyOID == (LPCSTR)1 && pPolicyPara && pPolicyPara->pvExtraPolicyPara) {
        SSL_EXTRA_CERT_CHAIN_POLICY_PARA* pSsl = (SSL_EXTRA_CERT_CHAIN_POLICY_PARA*)pPolicyPara->pvExtraPolicyPara;
        if (pSsl->pwszServerName) {
            LogMsg("[Crypto] SSL Target Hostname: '%ls'", pSsl->pwszServerName);
        }
    }
    if (pChainContext && pChainContext->cChain > 0 && pChainContext->rgpChain[0]->cElement > 0) {
        PCCERT_CONTEXT pCert = pChainContext->rgpChain[0]->rgpElement[0]->pCertContext;
        if (pCert) {
            wchar_t subject[256] = { 0 };
            CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, subject, 256);
            LogMsg("[Crypto] SSL Certificate Subject: '%ls'", subject);
        }
    }
    BOOL res = TRUE;
    if (g_real_CertVerifyCertificateChainPolicy) {
        res = g_real_CertVerifyCertificateChainPolicy(pszPolicyOID, pChainContext, pPolicyPara, pPolicyStatus);
    }
    if (pPolicyStatus) {
        pPolicyStatus->dwError = 0; // CERT_TRUST_NO_ERROR = 0
        pPolicyStatus->lChainIndex = -1;
        pPolicyStatus->lElementIndex = -1;
    }
    LogMsg("[Crypto] CertVerifyCertificateChainPolicy forced dwError=0 (SUCCESS)");
    return TRUE;
}

typedef BOOL (WINAPI *CertGetCertificateChain_t)(
    HCERTCHAINENGINE hChainEngine,
    PCCERT_CONTEXT pCertContext,
    LPFILETIME pTime,
    HCERTSTORE hAdditionalStore,
    PCERT_CHAIN_PARA pChainPara,
    DWORD dwFlags,
    LPVOID pvReserved,
    PCCERT_CHAIN_CONTEXT* ppChainContext
);
static CertGetCertificateChain_t g_real_CertGetCertificateChain = NULL;

static BOOL WINAPI Hook_CertGetCertificateChain(
    HCERTCHAINENGINE hChainEngine,
    PCCERT_CONTEXT pCertContext,
    LPFILETIME pTime,
    HCERTSTORE hAdditionalStore,
    PCERT_CHAIN_PARA pChainPara,
    DWORD dwFlags,
    LPVOID pvReserved,
    PCCERT_CHAIN_CONTEXT* ppChainContext
) {
    LogMsg("[Crypto] CertGetCertificateChain called");
    BOOL res = g_real_CertGetCertificateChain ? 
        g_real_CertGetCertificateChain(hChainEngine, pCertContext, pTime, hAdditionalStore, pChainPara, dwFlags, pvReserved, ppChainContext) : FALSE;

    if (res && ppChainContext && *ppChainContext) {
        CERT_CHAIN_CONTEXT* pCtx = (CERT_CHAIN_CONTEXT*)*ppChainContext;
        pCtx->TrustStatus.dwErrorStatus = 0; // CERT_TRUST_NO_ERROR
        for (DWORD c = 0; c < pCtx->cChain; c++) {
            if (pCtx->rgpChain[c]) {
                CERT_SIMPLE_CHAIN* pChain = (CERT_SIMPLE_CHAIN*)pCtx->rgpChain[c];
                pChain->TrustStatus.dwErrorStatus = 0;
            }
        }
        LogMsg("[Crypto] CertGetCertificateChain forced dwErrorStatus=0 (TRUSTED)");
    }
    return res;
}

// 2. WS2_32 Hooks
typedef int (WSAAPI *getaddrinfo_t)(
    PCSTR pNodeName,
    PCSTR pServiceName,
    const ADDRINFOA *pHints,
    PADDRINFOA *ppResult
);
static getaddrinfo_t g_real_getaddrinfo = NULL;

static int WSAAPI Hook_getaddrinfo(
    PCSTR pNodeName,
    PCSTR pServiceName,
    const ADDRINFOA *pHints,
    PADDRINFOA *ppResult
) {
    LogMsg("[DNS] getaddrinfo(node='%s', service='%s')", pNodeName ? pNodeName : "NULL", pServiceName ? pServiceName : "NULL");
    PCSTR node = pNodeName;
    PCSTR service = pServiceName;

    if (pNodeName && strcmp(pNodeName, "127.0.0.1") != 0 && strcmp(pNodeName, "localhost") != 0) {
        LogMsg("[Egress] Intercepted DNS getaddrinfo for '%s' -> Redirecting to '%s:%s'",
               pNodeName, g_server_ip, g_server_port);
        node = g_server_ip;
        if (pServiceName && (strcmp(pServiceName, "443") == 0 || strcmp(pServiceName, "https") == 0)) {
            service = g_server_port;
        }
    }

    int res = g_real_getaddrinfo ? g_real_getaddrinfo(node, service, pHints, ppResult) : WSAEFAULT;
    if (res != 0 && node == g_server_ip && g_real_getaddrinfo) {
        res = g_real_getaddrinfo(g_server_ip, service, NULL, ppResult);
    }
    return res;
}

typedef int (WSAAPI *GetAddrInfoW_t)(
    PCWSTR pNodeName,
    PCWSTR pServiceName,
    const ADDRINFOW *pHints,
    PADDRINFOW *ppResult
);
static GetAddrInfoW_t g_real_GetAddrInfoW = NULL;

static int WSAAPI Hook_GetAddrInfoW(
    PCWSTR pNodeName,
    PCWSTR pServiceName,
    const ADDRINFOW *pHints,
    PADDRINFOW *ppResult
) {
    if (pNodeName) {
        char nodeA[256] = {0};
        WideCharToMultiByte(CP_UTF8, 0, pNodeName, -1, nodeA, sizeof(nodeA), NULL, NULL);
        LogMsg("[DNS] GetAddrInfoW(node='%s')", nodeA);
        if (strcmp(nodeA, "127.0.0.1") != 0 && strcmp(nodeA, "localhost") != 0) {
            LogMsg("[Egress] Intercepted DNS GetAddrInfoW for '%s' -> Redirecting to '%s'", nodeA, g_server_ip);
            wchar_t wServerIp[64] = L"127.0.0.1";
            return g_real_GetAddrInfoW ? g_real_GetAddrInfoW(wServerIp, pServiceName, pHints, ppResult) : WSAEFAULT;
        }
    }
    return g_real_GetAddrInfoW ? g_real_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult) : WSAEFAULT;
}

typedef struct hostent* (WSAAPI *gethostbyname_t)(const char* name);
static gethostbyname_t g_real_gethostbyname = NULL;

static struct hostent* WSAAPI Hook_gethostbyname(const char* name) {
    LogMsg("[DNS] gethostbyname('%s')", name ? name : "NULL");
    if (name && strcmp(name, "127.0.0.1") != 0 && strcmp(name, "localhost") != 0) {
        LogMsg("[Egress] Intercepted DNS gethostbyname for '%s' -> Redirecting to '%s'",
               name, g_server_ip);
        return g_real_gethostbyname ? g_real_gethostbyname(g_server_ip) : NULL;
    }
    return g_real_gethostbyname ? g_real_gethostbyname(name) : NULL;
}

typedef int (WSAAPI *connect_t)(SOCKET s, const struct sockaddr* name, int namelen);
static connect_t g_real_connect = NULL;

static int WSAAPI Hook_connect(SOCKET s, const struct sockaddr* name, int namelen) {
    if (name) {
        if (name->sa_family == AF_INET) {
            struct sockaddr_in sin_copy;
            memcpy(&sin_copy, name, sizeof(sin_copy));
            uint16_t port = ntohs(sin_copy.sin_port);
            char ip[32] = {0};
            inet_ntop(AF_INET, &sin_copy.sin_addr, ip, sizeof(ip));
            LogMsg("[TCP] connect(IPv4) to %s:%d (socket=%lld)", ip, port, (long long)s);

            if (port == 443 || port == 80 || (strcmp(ip, "127.0.0.1") != 0 && (port == 8080 || port == 7777))) {
                uint16_t target_port = (port == 7777) ? 7777 : (uint16_t)atoi(g_server_port);
                LogMsg("[Egress] Redirecting IPv4 connect() from %s:%d to %s:%u",
                       ip, port, g_server_ip, target_port);
                sin_copy.sin_addr.s_addr = inet_addr(g_server_ip);
                sin_copy.sin_port = htons(target_port);
                return g_real_connect ? g_real_connect(s, (struct sockaddr*)&sin_copy, sizeof(sin_copy)) : SOCKET_ERROR;
            }
        } else if (name->sa_family == AF_INET6) {
            struct sockaddr_in6 sin6_copy;
            memcpy(&sin6_copy, name, sizeof(sin6_copy));
            uint16_t port = ntohs(sin6_copy.sin6_port);
            char ip6[64] = {0};
            inet_ntop(AF_INET6, &sin6_copy.sin6_addr, ip6, sizeof(ip6));
            LogMsg("[TCP] connect(IPv6) to [%s]:%d (socket=%lld)", ip6, port, (long long)s);

            if (port == 443 || port == 80 || port == 8080 || port == 7777) {
                uint16_t target_port = (port == 7777) ? 7777 : (uint16_t)atoi(g_server_port);
                LogMsg("[Egress] Redirecting IPv6 connect() to [::1]:%u", target_port);
                memset(&sin6_copy.sin6_addr, 0, sizeof(sin6_copy.sin6_addr));
                sin6_copy.sin6_addr.s6_addr[15] = 1;
                sin6_copy.sin6_port = htons(target_port);
                return g_real_connect ? g_real_connect(s, (struct sockaddr*)&sin6_copy, sizeof(sin6_copy)) : SOCKET_ERROR;
            }
        } else {
            LogMsg("[TCP] connect(family=%d)", name->sa_family);
        }
    }
    return g_real_connect ? g_real_connect(s, name, namelen) : SOCKET_ERROR;
}

typedef int (WSAAPI *WSAConnect_t)(
    SOCKET s,
    const struct sockaddr *name,
    int namelen,
    LPWSABUF lpCallerData,
    LPWSABUF lpCalleeData,
    LPQOS lpSQOS,
    LPQOS lpGQOS
);
static WSAConnect_t g_real_WSAConnect = NULL;

static int WSAAPI Hook_WSAConnect(
    SOCKET s,
    const struct sockaddr *name,
    int namelen,
    LPWSABUF lpCallerData,
    LPWSABUF lpCalleeData,
    LPQOS lpSQOS,
    LPQOS lpGQOS
) {
    if (name && name->sa_family == AF_INET) {
        struct sockaddr_in sin_copy;
        memcpy(&sin_copy, name, sizeof(sin_copy));
        uint16_t port = ntohs(sin_copy.sin_port);
        char ip[32] = {0};
        inet_ntop(AF_INET, &sin_copy.sin_addr, ip, sizeof(ip));
        LogMsg("[TCP] WSAConnect(IPv4) to %s:%d", ip, port);

        if (port == 443 || port == 80 || (strcmp(ip, "127.0.0.1") != 0 && (port == 8080 || port == 7777))) {
            uint16_t target_port = (port == 7777) ? 7777 : (uint16_t)atoi(g_server_port);
            LogMsg("[Egress] Redirecting IPv4 WSAConnect() from %s:%d to %s:%u",
                   ip, port, g_server_ip, target_port);
            sin_copy.sin_addr.s_addr = inet_addr(g_server_ip);
            sin_copy.sin_port = htons(target_port);
            return g_real_WSAConnect ? g_real_WSAConnect(s, (struct sockaddr*)&sin_copy, sizeof(sin_copy), lpCallerData, lpCalleeData, lpSQOS, lpGQOS) : SOCKET_ERROR;
        }
    }
    return g_real_WSAConnect ? g_real_WSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS) : SOCKET_ERROR;
}

// 3. WINHTTP Hooks
typedef HINTERNET (WINAPI *WinHttpConnect_t)(
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
        if (strcmp(sNameA, "127.0.0.1") != 0 && strcmp(sNameA, "localhost") != 0) {
            uint16_t target_port = (uint16_t)atoi(g_server_port);
            LogMsg("[Egress] Redirecting WinHttpConnect from '%s:%u' to 127.0.0.1:%u", sNameA, (unsigned int)nServerPort, target_port);
            return g_real_WinHttpConnect ? g_real_WinHttpConnect(hSession, L"127.0.0.1", (INTERNET_PORT)target_port, dwReserved) : NULL;
        }
    }
    return g_real_WinHttpConnect ? g_real_WinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved) : NULL;
}

// ---------------------------------------------------------------------------
// VFS & File Logging Hooks (KERNEL32!CreateFileW, CreateFileA)
// ---------------------------------------------------------------------------
typedef HANDLE (WINAPI *CreateFileW_t)(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
);
static CreateFileW_t g_real_CreateFileW = NULL;

static HANDLE WINAPI Hook_CreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
) {
    HANDLE h = g_real_CreateFileW ? g_real_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile) : INVALID_HANDLE_VALUE;
    DWORD err = (h == INVALID_HANDLE_VALUE) ? GetLastError() : 0;
    
    if (h == INVALID_HANDLE_VALUE) {
        if (lpFileName && !wcsstr(lpFileName, L"pipe\\\\") && !wcsstr(lpFileName, L"NUL")) {
            char nameA[MAX_PATH] = {0};
            WideCharToMultiByte(CP_UTF8, 0, lpFileName, -1, nameA, sizeof(nameA), NULL, NULL);
            LogMsg("[File-FAIL] CreateFileW('%s') -> INVALID_HANDLE_VALUE (err=%lu)", nameA, err);
        }
        SetLastError(err);
    } else {
        if (lpFileName && (wcsstr(lpFileName, L".pkg") || wcsstr(lpFileName, L"packages") || wcsstr(lpFileName, L"handle_map") || wcsstr(lpFileName, L"cache") || wcsstr(lpFileName, L"sku_config") || wcsstr(lpFileName, L".bin") || wcsstr(lpFileName, L".json") || wcsstr(lpFileName, L".txt"))) {
            char nameA[MAX_PATH] = {0};
            WideCharToMultiByte(CP_UTF8, 0, lpFileName, -1, nameA, sizeof(nameA), NULL, NULL);
            LogMsg("[File-OK] CreateFileW('%s') -> handle %p", nameA, h);
        }
    }
    return h;
}

typedef HANDLE (WINAPI *CreateFileA_t)(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
);
static CreateFileA_t g_real_CreateFileA = NULL;

static HANDLE WINAPI Hook_CreateFileA(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
) {
    HANDLE h = g_real_CreateFileA ? g_real_CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile) : INVALID_HANDLE_VALUE;
    DWORD err = (h == INVALID_HANDLE_VALUE) ? GetLastError() : 0;
    
    if (h == INVALID_HANDLE_VALUE) {
        if (lpFileName && !strstr(lpFileName, "pipe\\\\") && !strstr(lpFileName, "NUL")) {
            LogMsg("[File-FAIL] CreateFileA('%s') -> INVALID_HANDLE_VALUE (err=%lu)", lpFileName, err);
        }
        SetLastError(err);
    } else {
        if (lpFileName && (strstr(lpFileName, ".pkg") || strstr(lpFileName, "packages") || strstr(lpFileName, "handle_map") || strstr(lpFileName, "cache") || strstr(lpFileName, "sku_config") || strstr(lpFileName, ".bin") || strstr(lpFileName, ".json") || strstr(lpFileName, ".txt"))) {
            LogMsg("[File-OK] CreateFileA('%s') -> handle %p", lpFileName, h);
        }
    }
    return h;
}

// ---------------------------------------------------------------------------
// Module IAT Hooking
// ---------------------------------------------------------------------------
static void HookModuleIAT(HMODULE hMod, const char* targetModName) {
    if (!hMod) return;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((uint8_t*)hMod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    IMAGE_DATA_DIRECTORY importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress == 0 || importDir.Size == 0) return;

    PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)((uint8_t*)hMod + importDir.VirtualAddress);

    while (pImport->Name) {
        const char* modName = (const char*)((uint8_t*)hMod + pImport->Name);
        bool isWs2 = (_stricmp(modName, "WS2_32.dll") == 0);
        bool isK32 = (_stricmp(modName, "KERNEL32.dll") == 0);
        bool isCrypt = (_stricmp(modName, "CRYPT32.dll") == 0);

        if (isWs2 || isK32 || isCrypt) {
            uint32_t iltRVA = pImport->OriginalFirstThunk ? pImport->OriginalFirstThunk : pImport->FirstThunk;
            PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)((uint8_t*)hMod + iltRVA);
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((uint8_t*)hMod + pImport->FirstThunk);

            while (origThunk->u1.AddressOfData && thunk->u1.Function) {
                void* hook = NULL;
                const char* hookName = NULL;

                if (isWs2) {
                    if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                        uint16_t ord = (uint16_t)(origThunk->u1.Ordinal & 0xFFFF);
                        if (ord == 4) { hook = (void*)Hook_connect; hookName = "connect (ord 4)"; }
                        else if (ord == 52) { hook = (void*)Hook_gethostbyname; hookName = "gethostbyname (ord 52)"; }
                        else if (ord == 60) { hook = (void*)Hook_WSAConnect; hookName = "WSAConnect (ord 60)"; }
                    } else {
                        PIMAGE_IMPORT_BY_NAME impName = (PIMAGE_IMPORT_BY_NAME)((uint8_t*)hMod + origThunk->u1.AddressOfData);
                        const char* name = (const char*)impName->Name;
                        if (strcmp(name, "connect") == 0) { hook = (void*)Hook_connect; hookName = "connect"; }
                        else if (strcmp(name, "WSAConnect") == 0) { hook = (void*)Hook_WSAConnect; hookName = "WSAConnect"; }
                        else if (strcmp(name, "getaddrinfo") == 0) { hook = (void*)Hook_getaddrinfo; hookName = "getaddrinfo"; }
                        else if (strcmp(name, "GetAddrInfoW") == 0) { hook = (void*)Hook_GetAddrInfoW; hookName = "GetAddrInfoW"; }
                        else if (strcmp(name, "gethostbyname") == 0) { hook = (void*)Hook_gethostbyname; hookName = "gethostbyname"; }
                    }
                } else if (isCrypt) {
                    if (!(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                        PIMAGE_IMPORT_BY_NAME impName = (PIMAGE_IMPORT_BY_NAME)((uint8_t*)hMod + origThunk->u1.AddressOfData);
                        const char* name = (const char*)impName->Name;
                        if (strcmp(name, "CertVerifyCertificateChainPolicy") == 0) { hook = (void*)Hook_CertVerifyCertificateChainPolicy; hookName = "CertVerifyCertificateChainPolicy"; }
                        else if (strcmp(name, "CertGetCertificateChain") == 0) { hook = (void*)Hook_CertGetCertificateChain; hookName = "CertGetCertificateChain"; }
                    }
                } else if (isK32) {
                    if (!(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                        PIMAGE_IMPORT_BY_NAME impName = (PIMAGE_IMPORT_BY_NAME)((uint8_t*)hMod + origThunk->u1.AddressOfData);
                        const char* name = (const char*)impName->Name;
                        if (strcmp(name, "CreateFileW") == 0) { hook = (void*)Hook_CreateFileW; hookName = "CreateFileW"; }
                        else if (strcmp(name, "CreateFileA") == 0) { hook = (void*)Hook_CreateFileA; hookName = "CreateFileA"; }
                    }
                }

                if (hook && (void*)thunk->u1.Function != hook) {
                    DWORD oldProtect;
                    if (VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProtect)) {
                        thunk->u1.Function = (uintptr_t)hook;
                        VirtualProtect(&thunk->u1.Function, sizeof(void*), oldProtect, &oldProtect);
                        LogMsg("[%s] Successfully hooked %s!%s", targetModName, modName, hookName);
                    }
                }
                origThunk++;
                thunk++;
            }
        }
        pImport++;
    }
}

static bool g_partywin_hooked = false;
static bool g_libcurl_hooked = false;

static void CheckDynamicModules() {
    HMODULE hExe = GetModuleHandleA(NULL);
    if (hExe) {
        HookModuleIAT(hExe, "Marathon.exe");
    }
    if (!g_partywin_hooked) {
        HMODULE hParty = GetModuleHandleA("PartyWin.dll");
        if (hParty) {
            HookModuleIAT(hParty, "PartyWin.dll");
            g_partywin_hooked = true;
        }
    }
    if (!g_libcurl_hooked) {
        HMODULE hCurl = GetModuleHandleA("libcurl.dll");
        if (hCurl) {
            HookModuleIAT(hCurl, "libcurl.dll");
            g_libcurl_hooked = true;
        }
    }
}

static void InstallAllHooks() {
    // 1. WS2_32.dll - Inline Detours
    HMODULE hWs2 = GetModuleHandleA("WS2_32.dll");
    if (!hWs2) hWs2 = LoadLibraryA("WS2_32.dll");
    if (hWs2) {
        void* pConnect = (void*)GetProcAddress(hWs2, "connect");
        if (pConnect) {
            if (InstallInlineHook(pConnect, (void*)Hook_connect, 16, (void**)&g_real_connect)) {
                LogMsg("[InlineHook] Successfully detoured WS2_32.dll!connect");
            }
        }
        void* pWSAConnect = (void*)GetProcAddress(hWs2, "WSAConnect");
        if (pWSAConnect) {
            if (InstallInlineHook(pWSAConnect, (void*)Hook_WSAConnect, 16, (void**)&g_real_WSAConnect)) {
                LogMsg("[InlineHook] Successfully detoured WS2_32.dll!WSAConnect");
            }
        }
        void* pGetAddrInfo = (void*)GetProcAddress(hWs2, "getaddrinfo");
        if (pGetAddrInfo) {
            if (InstallInlineHook(pGetAddrInfo, (void*)Hook_getaddrinfo, 19, (void**)&g_real_getaddrinfo)) {
                LogMsg("[InlineHook] Successfully detoured WS2_32.dll!getaddrinfo");
            }
        }
        void* pGetAddrInfoW = (void*)GetProcAddress(hWs2, "GetAddrInfoW");
        if (pGetAddrInfoW) {
            if (InstallInlineHook(pGetAddrInfoW, (void*)Hook_GetAddrInfoW, 21, (void**)&g_real_GetAddrInfoW)) {
                LogMsg("[InlineHook] Successfully detoured WS2_32.dll!GetAddrInfoW");
            }
        }
        void* pGetHostByName = (void*)GetProcAddress(hWs2, "gethostbyname");
        if (pGetHostByName) {
            if (InstallInlineHook(pGetHostByName, (void*)Hook_gethostbyname, 19, (void**)&g_real_gethostbyname)) {
                LogMsg("[InlineHook] Successfully detoured WS2_32.dll!gethostbyname");
            }
        }
    }

    // 2. CRYPT32.dll - Inline Detours
    HMODULE hCrypt = GetModuleHandleA("CRYPT32.dll");
    if (!hCrypt) hCrypt = LoadLibraryA("CRYPT32.dll");
    if (hCrypt) {
        void* pCertVerify = (void*)GetProcAddress(hCrypt, "CertVerifyCertificateChainPolicy");
        if (pCertVerify) {
            if (InstallInlineHook(pCertVerify, (void*)Hook_CertVerifyCertificateChainPolicy, 19, (void**)&g_real_CertVerifyCertificateChainPolicy)) {
                LogMsg("[InlineHook] Successfully detoured CRYPT32.dll!CertVerifyCertificateChainPolicy");
            }
        }
        void* pCertGetChain = (void*)GetProcAddress(hCrypt, "CertGetCertificateChain");
        if (pCertGetChain) {
            if (InstallInlineHook(pCertGetChain, (void*)Hook_CertGetCertificateChain, 16, (void**)&g_real_CertGetCertificateChain)) {
                LogMsg("[InlineHook] Successfully detoured CRYPT32.dll!CertGetCertificateChain");
            }
        }
    }

    // 3. WINHTTP.dll - Inline Detours
    HMODULE hWinHttp = GetModuleHandleA("WINHTTP.dll");
    if (!hWinHttp) hWinHttp = LoadLibraryA("WINHTTP.dll");
    if (hWinHttp) {
        void* pWinHttpConnect = (void*)GetProcAddress(hWinHttp, "WinHttpConnect");
        if (pWinHttpConnect) {
            if (InstallInlineHook(pWinHttpConnect, (void*)Hook_WinHttpConnect, 21, (void**)&g_real_WinHttpConnect)) {
                LogMsg("[InlineHook] Successfully detoured WINHTTP.dll!WinHttpConnect");
            }
        }
    }

    // 4. KERNEL32.dll file logging
    HMODULE hK32 = GetModuleHandleA("KERNEL32.dll");
    if (hK32) {
        g_real_CreateFileW = (CreateFileW_t)GetProcAddress(hK32, "CreateFileW");
        g_real_CreateFileA = (CreateFileA_t)GetProcAddress(hK32, "CreateFileA");
    }

    // 5. Dynamic Module IAT hooking
    CheckDynamicModules();
}"""

updated = content[:pos1] + new_code + content[pos2:]
updated = updated.replace("InstallIATHooks();", "InstallAllHooks();")

with open(cpp_path, "w", encoding="utf-8") as f:
    f.write(updated)

print("Updated steam_api64.cpp successfully!")
