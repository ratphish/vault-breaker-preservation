import os

filepath = r'D:\vault-breaker-preservation\client_proxy\steam_api64.cpp'
with open(filepath, 'r', encoding='utf-8') as f:
    code = f.read()

# 1. Update Hook_CertVerifyCertificateChainPolicy to log original res and dwError
old_cert = '''    BOOL res = TRUE;
    if (g_real_CertVerifyCertificateChainPolicy) {
        res = g_real_CertVerifyCertificateChainPolicy(pszPolicyOID, pChainContext, pPolicyPara, pPolicyStatus);
    }
    if (pPolicyStatus) {
        pPolicyStatus->dwError = 0; // CERT_TRUST_NO_ERROR = 0
    }
    LogMsg("[Crypto] CertVerifyCertificateChainPolicy (%s) -> Forcing SUCCESS", policyDesc);
    return TRUE;'''

new_cert = '''    DWORD dwErrorBefore = pPolicyStatus ? pPolicyStatus->dwError : 0xFFFFFFFF;
    BOOL realRes = FALSE;
    if (g_real_CertVerifyCertificateChainPolicy) {
        realRes = g_real_CertVerifyCertificateChainPolicy(pszPolicyOID, pChainContext, pPolicyPara, pPolicyStatus);
    }
    DWORD dwErrorAfter = pPolicyStatus ? pPolicyStatus->dwError : 0xFFFFFFFF;
    LogMsg("[Crypto] CertVerifyCertificateChainPolicy (%s) -> realRes=%d, dwErrorBefore=0x%08X, dwErrorAfter=0x%08X",
           policyDesc, realRes, dwErrorBefore, dwErrorAfter);
    if (pPolicyStatus && pPolicyStatus->dwError != 0) {
        LogMsg("[Crypto] Natural chain error detected (0x%08X), normalizing to NO_ERROR for local emulation", pPolicyStatus->dwError);
        pPolicyStatus->dwError = 0; // CERT_TRUST_NO_ERROR = 0
    }
    return TRUE;'''
assert old_cert in code, "old_cert not found"
code = code.replace(old_cert, new_cert)

# 2. Attach missing hooks in HookModuleIAT
old_iat_thunk = '''                if (isWs2) {
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

                        else if (strcmp(name, "GetAddrInfoExW") == 0) { hook = (void*)Hook_GetAddrInfoExW; hookName = "GetAddrInfoExW"; }

                        else if (strcmp(name, "gethostbyname") == 0) { hook = (void*)Hook_gethostbyname; hookName = "gethostbyname"; }

                    }

                } else if (isCrypt) {
                    if (!(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                        PIMAGE_IMPORT_BY_NAME impName = (PIMAGE_IMPORT_BY_NAME)((uint8_t*)hMod + origThunk->u1.AddressOfData);
                        const char* name = (const char*)impName->Name;
                        if (strcmp(name, "CertVerifyCertificateChainPolicy") == 0) { hook = (void*)Hook_CertVerifyCertificateChainPolicy; hookName = "CertVerifyCertificateChainPolicy"; }

                    }

                } else if (isK32) {
                    if (!(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                        PIMAGE_IMPORT_BY_NAME impName = (PIMAGE_IMPORT_BY_NAME)((uint8_t*)hMod + origThunk->u1.AddressOfData);
                        const char* name = (const char*)impName->Name;
                        if (strcmp(name, "CreateFileW") == 0) { hook = (void*)Hook_CreateFileW; hookName = "CreateFileW"; }

                        else if (strcmp(name, "CreateFileA") == 0) { hook = (void*)Hook_CreateFileA; hookName = "CreateFileA"; }

                    }

                }'''

new_iat_thunk = '''                if (isWs2) {
                    if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                        uint16_t ord = (uint16_t)(origThunk->u1.Ordinal & 0xFFFF);
                        if (ord == 4) { hook = (void*)Hook_connect; hookName = "connect (ord 4)"; }
                        else if (ord == 17) { hook = (void*)Hook_sendto; hookName = "sendto (ord 17)"; }
                        else if (ord == 46 || ord == 60) { hook = (void*)Hook_WSAConnect; hookName = "WSAConnect (ord 46/60)"; }
                        else if (ord == 52) { hook = (void*)Hook_gethostbyname; hookName = "gethostbyname (ord 52)"; }
                    } else {
                        PIMAGE_IMPORT_BY_NAME impName = (PIMAGE_IMPORT_BY_NAME)((uint8_t*)hMod + origThunk->u1.AddressOfData);
                        const char* name = (const char*)impName->Name;
                        if (strcmp(name, "connect") == 0) { hook = (void*)Hook_connect; hookName = "connect"; }
                        else if (strcmp(name, "WSAConnect") == 0) { hook = (void*)Hook_WSAConnect; hookName = "WSAConnect"; }
                        else if (strcmp(name, "WSAIoctl") == 0) { hook = (void*)Hook_WSAIoctl; hookName = "WSAIoctl"; }
                        else if (strcmp(name, "sendto") == 0) { hook = (void*)Hook_sendto; hookName = "sendto"; }
                        else if (strcmp(name, "WSASendTo") == 0) { hook = (void*)Hook_WSASendTo; hookName = "WSASendTo"; }
                        else if (strcmp(name, "getaddrinfo") == 0) { hook = (void*)Hook_getaddrinfo; hookName = "getaddrinfo"; }
                        else if (strcmp(name, "GetAddrInfoW") == 0) { hook = (void*)Hook_GetAddrInfoW; hookName = "GetAddrInfoW"; }
                        else if (strcmp(name, "GetAddrInfoExW") == 0) { hook = (void*)Hook_GetAddrInfoExW; hookName = "GetAddrInfoExW"; }
                        else if (strcmp(name, "gethostbyname") == 0) { hook = (void*)Hook_gethostbyname; hookName = "gethostbyname"; }
                    }
                } else if (isCrypt) {
                    if (!(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                        PIMAGE_IMPORT_BY_NAME impName = (PIMAGE_IMPORT_BY_NAME)((uint8_t*)hMod + origThunk->u1.AddressOfData);
                        const char* name = (const char*)impName->Name;
                        if (strcmp(name, "CertVerifyCertificateChainPolicy") == 0) { hook = (void*)Hook_CertVerifyCertificateChainPolicy; hookName = "CertVerifyCertificateChainPolicy"; }
                    }
                } else if (isK32) {
                    if (!(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                        PIMAGE_IMPORT_BY_NAME impName = (PIMAGE_IMPORT_BY_NAME)((uint8_t*)hMod + origThunk->u1.AddressOfData);
                        const char* name = (const char*)impName->Name;
                        if (strcmp(name, "CreateFileW") == 0) { hook = (void*)Hook_CreateFileW; hookName = "CreateFileW"; }
                        else if (strcmp(name, "CreateFileA") == 0) { hook = (void*)Hook_CreateFileA; hookName = "CreateFileA"; }
                        else if (strcmp(name, "GetProcAddress") == 0) { hook = (void*)Hook_GetProcAddress; hookName = "GetProcAddress"; }
                    }
                }'''
assert old_iat_thunk in code, "old_iat_thunk not found"
code = code.replace(old_iat_thunk, new_iat_thunk)

# 3. Update InstallIATHooks to fetch missing g_real pointers
old_install_ws2 = '''        g_real_connect = (connect_t)GetProcAddress(hWs2, "connect");
        g_real_WSAConnect = (WSAConnect_t)GetProcAddress(hWs2, "WSAConnect");
    }'''

new_install_ws2 = '''        g_real_connect = (connect_t)GetProcAddress(hWs2, "connect");
        g_real_WSAConnect = (WSAConnect_t)GetProcAddress(hWs2, "WSAConnect");
        g_real_WSAIoctl = (WSAIoctl_t)GetProcAddress(hWs2, "WSAIoctl");
        g_real_sendto = (sendto_t)GetProcAddress(hWs2, "sendto");
        g_real_WSASendTo = (WSASendTo_t)GetProcAddress(hWs2, "WSASendTo");
    }'''
assert old_install_ws2 in code, "old_install_ws2 not found"
code = code.replace(old_install_ws2, new_install_ws2)

with open(filepath, 'w', encoding='utf-8') as f:
    f.write(code)
print('Successfully attached all missing network hooks and certificate diagnostics!')
