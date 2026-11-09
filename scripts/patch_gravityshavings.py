import re

path = r'D:\vault-breaker-preservation\client_proxy\steam_api64.cpp'
with open(path, 'r', encoding='utf-8') as f:
    code = f.read()

# Normalize line endings in memory
code = code.replace('\r\n', '\n')

# 1. Add gravityshavings to domain filters
code = code.replace(
    'strstr(pNodeName, "playfab")',
    'strstr(pNodeName, "playfab") || strstr(pNodeName, "gravityshavings")'
)
code = code.replace(
    'strstr(nodeA, "playfab")',
    'strstr(nodeA, "playfab") || strstr(nodeA, "gravityshavings")'
)
code = code.replace(
    'strstr(name, "playfab")',
    'strstr(name, "playfab") || strstr(name, "gravityshavings")'
)
code = code.replace(
    'strstr(sNameA, "playfab")',
    'strstr(sNameA, "playfab") || strstr(sNameA, "gravityshavings")'
)

# 2. Add GetAddrInfoExW hook
getaddrinfoex_code = """
typedef INT (WSAAPI *GetAddrInfoExW_t)(
    PCWSTR pName,
    PCWSTR pServiceName,
    DWORD dwNamespace,
    LPGUID lpNspId,
    const ADDRINFOEXW *pHints,
    PADDRINFOEXW *ppResult,
    struct timeval *timeout,
    LPOVERLAPPED lpOverlapped,
    LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine,
    LPHANDLE lpNameHandle
);
static GetAddrInfoExW_t g_real_GetAddrInfoExW = NULL;

static INT WSAAPI Hook_GetAddrInfoExW(
    PCWSTR pName,
    PCWSTR pServiceName,
    DWORD dwNamespace,
    LPGUID lpNspId,
    const ADDRINFOEXW *pHints,
    PADDRINFOEXW *ppResult,
    struct timeval *timeout,
    LPOVERLAPPED lpOverlapped,
    LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine,
    LPHANDLE lpNameHandle
) {
    PCWSTR node = pName;
    if (pName) {
        char nodeA[256] = {0};
        WideCharToMultiByte(CP_UTF8, 0, pName, -1, nodeA, sizeof(nodeA), NULL, NULL);
        LogMsg("[DNS] GetAddrInfoExW(node='%s')", nodeA);
        if (strstr(nodeA, "deadorbit") || strstr(nodeA, "bungie") || strstr(nodeA, "goliath") ||
            strstr(nodeA, "marathon") || strstr(nodeA, "playfab") || strstr(nodeA, "gravityshavings")) {
            LogMsg("[Egress] Intercepted DNS GetAddrInfoExW for '%s' -> Redirecting to 127.0.0.1", nodeA);
            wchar_t wServerIp[64] = L"127.0.0.1";
            return g_real_GetAddrInfoExW ?
                g_real_GetAddrInfoExW(wServerIp, pServiceName, dwNamespace, lpNspId, pHints, ppResult, timeout, lpOverlapped, lpCompletionRoutine, lpNameHandle) :
                WSAEFAULT;
        }
    }
    return g_real_GetAddrInfoExW ?
        g_real_GetAddrInfoExW(node, pServiceName, dwNamespace, lpNspId, pHints, ppResult, timeout, lpOverlapped, lpCompletionRoutine, lpNameHandle) :
        WSAEFAULT;
}
"""

# Place GetAddrInfoExW hook right after Hook_GetAddrInfoW
target_gw = "return g_real_GetAddrInfoW ? g_real_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult) : WSAEFAULT;\n}"
assert target_gw in code, "target_gw not found"
code = code.replace(target_gw, target_gw + "\n" + getaddrinfoex_code, 1)

# In HookModuleIAT, add GetAddrInfoExW handling
target_hook_name = 'else if (strcmp(name, "GetAddrInfoW") == 0) { hook = (void*)Hook_GetAddrInfoW; hookName = "GetAddrInfoW"; }'
replacement_hook_name = target_hook_name + '\n                        else if (strcmp(name, "GetAddrInfoExW") == 0) { hook = (void*)Hook_GetAddrInfoExW; hookName = "GetAddrInfoExW"; }'
assert target_hook_name in code, "target_hook_name not found"
code = code.replace(target_hook_name, replacement_hook_name, 1)

# In InstallIATHooks, resolve GetAddrInfoExW
target_resolve = 'g_real_GetAddrInfoW = (GetAddrInfoW_t)GetProcAddress(hWs2, "GetAddrInfoW");'
replacement_resolve = target_resolve + '\n        g_real_GetAddrInfoExW = (GetAddrInfoExW_t)GetProcAddress(hWs2, "GetAddrInfoExW");'
assert target_resolve in code, "target_resolve not found"
code = code.replace(target_resolve, replacement_resolve, 1)

with open(path, 'w', encoding='utf-8', newline='\r\n') as f:
    f.write(code.replace('\n', '\r\n'))

print("[+] Successfully added gravityshavings redirection and GetAddrInfoExW hook!")
