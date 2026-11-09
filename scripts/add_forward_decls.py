import os

filepath = r'D:\vault-breaker-preservation\client_proxy\steam_api64.cpp'
with open(filepath, 'r', encoding='utf-8') as f:
    code = f.read()

target = 'typedef FARPROC (WINAPI *GetProcAddress_t)(HMODULE hModule, LPCSTR lpProcName);'

fwd_decls = '''static int WSAAPI Hook_connect(SOCKET s, const struct sockaddr* name, int namelen);
static int WSAAPI Hook_WSAConnect(SOCKET s, const struct sockaddr *name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS);
static int WSAAPI Hook_getaddrinfo(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA *pHints, PADDRINFOA *ppResult);
static int WSAAPI Hook_GetAddrInfoW(PCWSTR pNodeName, PCWSTR pServiceName, const ADDRINFOW *pHints, PADDRINFOW *ppResult);
static INT WSAAPI Hook_GetAddrInfoExW(PCWSTR pName, PCWSTR pServiceName, DWORD dwNamespace, LPGUID lpNspId, const ADDRINFOEXW *pHints, PADDRINFOEXW *ppResult, struct timeval *timeout, LPOVERLAPPED lpOverlapped, LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine, LPHANDLE lpNameHandle);
'''

assert target in code, "target not found"
code = code.replace(target, fwd_decls + '\n' + target)

with open(filepath, 'w', encoding='utf-8') as f:
    f.write(code)
print('Added forward declarations!')
