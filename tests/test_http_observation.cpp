// Standalone helper. DllMain is not run; no production proxy DLL is loaded.
// Only synthetic import tables are patched. HTTP calls are stubbed.
#include "../client_proxy/steam_api64.cpp"
#include <assert.h>

static unsigned checks = 0;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); return 1; } } while (0)
static unsigned performCalls, addCalls, readCalls, infoCalls, sendCalls, receiveCalls;
static unsigned pumpCalls, socketActionCalls;
static bool badArguments;
static unsigned httpReadCalls, availableCalls, headersCalls, callbackCalls;
static bool failHeaders;
static void CALLBACK NativeCallback(HINTERNET, DWORD_PTR, DWORD, LPVOID, DWORD) {}
static BOOL WINAPI FakeHttpRead(HINTERNET request, LPVOID buffer, DWORD count, LPDWORD read) {
    ++httpReadCalls; badArguments |= request != (void*)0x5555 || buffer != (void*)0x2222 || count != 42;
    if (read) *read = 17;
    SetLastError(1234); errno = EDOM; return TRUE;
}
static BOOL WINAPI FakeAvailable(HINTERNET request, LPDWORD available) {
    ++availableCalls; badArguments |= request != (void*)0x5555;
    if (available) *available = 29;
    SetLastError(1234); errno = EDOM; return TRUE;
}
static BOOL WINAPI FakeHeaders(HINTERNET request, DWORD level, LPCWSTR name, LPVOID buffer, LPDWORD length, LPDWORD index) {
    ++headersCalls; badArguments |= request != (void*)0x5555 || name != NULL || index != NULL ||
        level != (WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER);
    if (!failHeaders) { *(DWORD*)buffer = 200; *length = sizeof(DWORD); }
    SetLastError(failHeaders ? ERROR_INSUFFICIENT_BUFFER : 1234); errno = EDOM;
    return failHeaders ? FALSE : TRUE;
}
static WINHTTP_STATUS_CALLBACK WINAPI FakeCallback(HINTERNET handle, WINHTTP_STATUS_CALLBACK callback, DWORD flags, DWORD_PTR reserved) {
    ++callbackCalls; badArguments |= handle != (void*)0x5555 || callback != NativeCallback || flags != 0x123 || reserved != 0;
    SetLastError(1234); errno = EDOM; return (WINHTTP_STATUS_CALLBACK)0x7777;
}
static CurlMessage message = {};
static bool noMessage;
static int __cdecl FakePassivePerform(void* easy) {
    badArguments |= easy != (void*)0x1234 || GetLastError() != 6789 || errno != EILSEQ;
    return 5; // Leaves both error values unchanged.
}
static int __cdecl FakePerform(void* easy) {
    ++performCalls; badArguments |= easy != (void*)0x1234;
    SetLastError(1234); errno = EDOM; return 28;
}
static int __cdecl FakeAdd(void* multi, void* easy) {
    ++addCalls; badArguments |= multi != (void*)0x4321 || easy != (void*)0x1234;
    SetLastError(1234); errno = EDOM; return 7;
}
static CurlMessage* __cdecl FakeRead(void* multi, int* queued) {
    ++readCalls; badArguments |= multi != (void*)0x4321;
    *queued = noMessage ? 0 : 2;
    SetLastError(1234); errno = EDOM;
    return noMessage ? NULL : &message;
}
static int __cdecl FakeInfo(void* easy, int field, ...) {
    ++infoCalls; badArguments |= easy != (void*)0x1234;
    va_list args; va_start(args, field);
    if (field == 0x100001) *va_arg(args, char**) = (char*)"https://127.0.0.1/SignOn?secret=do-not-log";
    else if (field == 0x200002) *va_arg(args, long*) = 200;
    else badArguments = true;
    va_end(args);
    SetLastError(999); errno = ERANGE; return 0;
}
static BOOL WINAPI FakeSend(HINTERNET request, LPCWSTR headers, DWORD headerLength,
                           LPVOID body, DWORD bodyLength, DWORD total, DWORD_PTR context) {
    ++sendCalls;
    badArguments |= request != (void*)0x5555 || headers != (LPCWSTR)0x1111 || headerLength != 33 ||
                     body != (void*)0x2222 || bodyLength != 42 || total != 99 || context != 0xfedc;
    SetLastError(ERROR_IO_PENDING); errno = EDOM; return TRUE;
}
static BOOL WINAPI FakeReceive(HINTERNET request, LPVOID reserved) {
    ++receiveCalls; badArguments |= request != (void*)0x5555 || reserved != NULL;
    SetLastError(ERROR_CONNECTION_ABORTED); errno = EDOM; return FALSE;
}
static int __cdecl FakePump(void* multi, int* running) {
    ++pumpCalls; badArguments |= multi != (void*)0x4321 || !running;
    *running = 3; SetLastError(1234); errno = EDOM; return 0;
}
static int __cdecl FakeSocketAction(void* multi, SOCKET socket, int events, int* running) {
    ++socketActionCalls;
    badArguments |= multi != (void*)0x4321 || socket != 0x7001 || events != 6 || !running;
    *running = 2; SetLastError(1234); errno = EDOM; return 0;
}

static void SetNativeSocketExports() {
    HMODULE ws = GetModuleHandleA("ws2_32.dll");
    g_real_connect = (connect_t)::GetProcAddress(ws, "connect");
    g_real_WSAConnect = (WSAConnect_t)::GetProcAddress(ws, "WSAConnect");
    g_real_WSAIoctl = (WSAIoctl_t)::GetProcAddress(ws, "WSAIoctl");
    g_real_sendto = (sendto_t)::GetProcAddress(ws, "sendto");
    g_real_WSASendTo = (WSASendTo_t)::GetProcAddress(ws, "WSASendTo");
    g_real_getaddrinfo = (getaddrinfo_t)::GetProcAddress(ws, "getaddrinfo");
    g_real_GetAddrInfoW = (GetAddrInfoW_t)::GetProcAddress(ws, "GetAddrInfoW");
    g_real_GetAddrInfoExW = (GetAddrInfoExW_t)::GetProcAddress(ws, "GetAddrInfoExW");
    g_real_gethostbyname = (gethostbyname_t)::GetProcAddress(ws, "gethostbyname");
    g_real_GetProcAddress = ::GetProcAddress;
}

static int TestResolverAndIAT() {
    SetNativeSocketExports();
    HMODULE ws = GetModuleHandleA("ws2_32.dll");
    FARPROC recvfromExport = ::GetProcAddress(ws, (LPCSTR)17);
    FARPROC sendtoExport = ::GetProcAddress(ws, (LPCSTR)20);
    CHECK(recvfromExport == ::GetProcAddress(ws, "recvfrom"));
    CHECK(sendtoExport == ::GetProcAddress(ws, "sendto"));
    CHECK(SocketObservationBinding(recvfromExport).hook == NULL);
    CHECK(SocketObservationBinding(sendtoExport).hook == (void*)Hook_sendto);
    CHECK(SocketObservationBinding(::GetProcAddress(ws, (LPCSTR)60)).hook == NULL);
    CHECK(Hook_GetProcAddress(ws, (LPCSTR)17) == recvfromExport);
    CHECK(Hook_GetProcAddress(ws, (LPCSTR)20) == (FARPROC)Hook_sendto);
    CHECK(Hook_GetProcAddress(ws, "connect") == (FARPROC)Hook_connect);
    HMODULE kernel = GetModuleHandleA("kernel32.dll");
    CHECK(Hook_GetProcAddress(kernel, (LPCSTR)4) == ::GetProcAddress(kernel, (LPCSTR)4));
    CHECK(Hook_GetProcAddress(kernel, "GetProcAddress") == (FARPROC)Hook_GetProcAddress);
    CHECK(Hook_GetProcAddress(kernel, "NoSuchMarathonBootstrapExport") == NULL);
    CHECK(GetLastError() == ERROR_PROC_NOT_FOUND);

    unsigned char* memory = (unsigned char*)VirtualAlloc(NULL, 0x4000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    CHECK(memory != NULL);
    auto dos = (IMAGE_DOS_HEADER*)memory; dos->e_magic = IMAGE_DOS_SIGNATURE; dos->e_lfanew = 0x80;
    auto nt = (IMAGE_NT_HEADERS*)(memory + 0x80); nt->Signature = IMAGE_NT_SIGNATURE;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] = {0x1000, 60};
    auto imports = (IMAGE_IMPORT_DESCRIPTOR*)(memory + 0x1000);
    imports[0].Name = 0x1100; strcpy((char*)memory + 0x1100, "KERNEL32.dll");
    imports[0].OriginalFirstThunk = 0x1200; imports[0].FirstThunk = 0x1300;
    auto loaderNames = (IMAGE_THUNK_DATA*)(memory + 0x1200);
    auto loaderSlots = (IMAGE_THUNK_DATA*)(memory + 0x1300);
    loaderNames[0].u1.AddressOfData = 0x1400;
    strcpy((char*)memory + 0x1402, "GetProcAddress");
    loaderSlots[0].u1.Function = (uintptr_t)::GetProcAddress;
    imports[1].Name = 0x1500; strcpy((char*)memory + 0x1500, "WS2_32.dll");
    imports[1].OriginalFirstThunk = 0x1600; imports[1].FirstThunk = 0x1700;
    auto names = (IMAGE_THUNK_DATA*)(memory + 0x1600);
    auto slots = (IMAGE_THUNK_DATA*)(memory + 0x1700);
    names[0].u1.Ordinal = IMAGE_ORDINAL_FLAG | 17; slots[0].u1.Function = (uintptr_t)recvfromExport;
    names[1].u1.Ordinal = IMAGE_ORDINAL_FLAG | 20; slots[1].u1.Function = (uintptr_t)sendtoExport;
    names[2].u1.Ordinal = IMAGE_ORDINAL_FLAG | 60; slots[2].u1.Function = (uintptr_t)::GetProcAddress(ws, (LPCSTR)60);
    const uintptr_t namespaceExport = slots[2].u1.Function;
    HookModuleIAT((HMODULE)memory, "synthetic-IAT-test");
    CHECK(loaderSlots[0].u1.Function == (uintptr_t)Hook_GetProcAddress);
    CHECK(slots[0].u1.Function == (uintptr_t)recvfromExport);
    CHECK(slots[1].u1.Function == (uintptr_t)Hook_sendto);
    CHECK(slots[2].u1.Function == namespaceExport);
    // Re-scan is idempotent and does not reinterpret names from the live IAT.
    HookModuleIAT((HMODULE)memory, "synthetic-IAT-test");
    CHECK(slots[0].u1.Function == (uintptr_t)recvfromExport);
    CHECK(slots[1].u1.Function == (uintptr_t)Hook_sendto);
    CHECK(VirtualFree(memory, 0, MEM_RELEASE));
    return 0;
}

static int TestCurlExportBinding() {
    // Map the supplied DLL for export lookup ONLY. Do not initialize it or
    // invoke its code; all observer behavior is tested separately with stubs.
    HMODULE curl = LoadLibraryExA("D:\\Marathon-live\\bin\\x64\\libcurl.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
    CHECK(curl != NULL);
    FARPROC perform = ::GetProcAddress(curl, "curl_easy_perform");
    CHECK((uintptr_t)perform - (uintptr_t)curl == 0x18990);
    CHECK(Hook_GetProcAddress(curl, "curl_easy_perform") == (FARPROC)ObserveCurlPerform);
    CHECK(Hook_GetProcAddress(curl, (LPCSTR)12) == (FARPROC)ObserveCurlPerform);
    CHECK(Hook_GetProcAddress(curl, "curl_multi_add_handle") == (FARPROC)ObserveCurlAdd);
    CHECK(Hook_GetProcAddress(curl, (LPCSTR)49) == (FARPROC)ObserveCurlAdd);
    CHECK(Hook_GetProcAddress(curl, "curl_multi_info_read") == (FARPROC)ObserveCurlRead);
    CHECK(Hook_GetProcAddress(curl, (LPCSTR)54) == (FARPROC)ObserveCurlRead);
    CHECK(Hook_GetProcAddress(curl, "curl_multi_perform") == (FARPROC)ObserveCurlMultiPerform);
    CHECK(Hook_GetProcAddress(curl, (LPCSTR)56) == (FARPROC)ObserveCurlMultiPerform);
    CHECK(Hook_GetProcAddress(curl, "curl_multi_socket_action") == (FARPROC)ObserveCurlSocketAction);
    CHECK(Hook_GetProcAddress(curl, (LPCSTR)61) == (FARPROC)ObserveCurlSocketAction);
    CHECK(Hook_GetProcAddress(curl, "curl_easy_setopt") == ::GetProcAddress(curl, "curl_easy_setopt"));
    CHECK(Hook_GetProcAddress(curl, (LPCSTR)16) == ::GetProcAddress(curl, (LPCSTR)16));
    CHECK(Hook_GetProcAddress(curl, "curl_easy_getinfo") == ::GetProcAddress(curl, "curl_easy_getinfo"));
    CHECK(FreeLibrary(curl));
    g_curl_perform.store(nullptr); g_curl_add.store(nullptr); g_curl_read.store(nullptr); g_curl_info.store(nullptr);
    g_observed_curl_module.store(nullptr);
    g_curl_multi_perform.store(nullptr); g_curl_socket_action.store(nullptr);
    return 0;
}

int main() {
    strcpy_s(g_log_path, "NUL");
    if (TestResolverAndIAT()) return 1;
    if (TestCurlExportBinding()) return 1;
    char route[256];
    HttpRouteForLog("https://host/path?token=secret#fragment", route, sizeof(route));
    CHECK(strcmp(route, "https://host/path") == 0);
    HttpRouteForLog("https://user:password@host/path", route, sizeof(route));
    CHECK(strcmp(route, "<userinfo-url-redacted>") == 0);
    char longUrl[600] = "https://"; memset(longUrl + 8, 'x', 500);
    strcpy(longUrl + 508, "@host/path");
    HttpRouteForLog(longUrl, route, sizeof(route));
    CHECK(strcmp(route, "<userinfo-url-redacted>") == 0);
    g_curl_perform.store(FakePerform); g_curl_add.store(FakeAdd); g_curl_read.store(FakeRead); g_curl_info.store(FakeInfo);
    CHECK(ObserveCurlPerform((void*)0x1234) == 28);
    CHECK(GetLastError() == 1234 && errno == EDOM);
    CHECK(performCalls == 1 && infoCalls == 2);
    CHECK(ObserveCurlAdd((void*)0x4321, (void*)0x1234) == 7);
    CHECK(GetLastError() == 1234 && errno == EDOM);
    CHECK(addCalls == 1 && infoCalls == 2);
    message.type = 1; message.easy = (void*)0x1234; message.data.result = 18;
    const CurlMessage before = message;
    int queued = 99;
    CHECK(ObserveCurlRead((void*)0x4321, &queued) == &message);
    CHECK(GetLastError() == 1234 && errno == EDOM);
    CHECK(readCalls == 1 && queued == 2 && infoCalls == 4);
    CHECK(memcmp(&message, &before, sizeof(message)) == 0);
    noMessage = true;
    CHECK(ObserveCurlRead((void*)0x4321, &queued) == NULL);
    CHECK(GetLastError() == 1234 && errno == EDOM);
    CHECK(readCalls == 2 && queued == 0 && infoCalls == 4);
    g_http_send.store(FakeSend); g_http_receive.store(FakeReceive);
    CHECK(ObserveHttpSend((void*)0x5555, (LPCWSTR)0x1111, 33, (void*)0x2222, 42, 99, 0xfedc) == TRUE);
    CHECK(GetLastError() == ERROR_IO_PENDING && errno == EDOM);
    CHECK(ObserveHttpReceive((void*)0x5555, NULL) == FALSE);
    CHECK(GetLastError() == ERROR_CONNECTION_ABORTED && errno == EDOM);
    CHECK(sendCalls == 1 && receiveCalls == 1 && !badArguments);
    SetLastError(3456); errno = EDOM; LogMsg("[HTTPTrace] logging-error-state-test");
    CHECK(GetLastError() == 3456 && errno == EDOM);
    g_curl_perform.store(FakePassivePerform);
    SetLastError(6789); errno = EILSEQ;
    CHECK(ObserveCurlPerform((void*)0x1234) == 5);
    CHECK(GetLastError() == 6789 && errno == EILSEQ && !badArguments);
    g_curl_multi_perform.store(FakePump); g_curl_socket_action.store(FakeSocketAction);
    int running = 0;
    CHECK(ObserveCurlMultiPerform((void*)0x4321, &running) == 0 && running == 3);
    CHECK(GetLastError() == 1234 && errno == EDOM && pumpCalls == 1);
    CHECK(ObserveCurlSocketAction((void*)0x4321, 0x7001, 6, &running) == 0 && running == 2);
    CHECK(GetLastError() == 1234 && errno == EDOM && socketActionCalls == 1 && !badArguments);
    g_http_read.store(FakeHttpRead); g_http_available.store(FakeAvailable);
    g_http_headers.store(FakeHeaders); g_http_callback.store(FakeCallback);
    DWORD transferred = 0;
    CHECK(ObserveHttpRead((void*)0x5555, (void*)0x2222, 42, &transferred) == TRUE && transferred == 17);
    CHECK(GetLastError() == 1234 && errno == EDOM && httpReadCalls == 1);
    CHECK(ObserveHttpRead((void*)0x5555, (void*)0x2222, 42, NULL) == TRUE);
    CHECK(GetLastError() == 1234 && errno == EDOM && httpReadCalls == 2);
    CHECK(ObserveHttpAvailable((void*)0x5555, &transferred) == TRUE && transferred == 29);
    CHECK(GetLastError() == 1234 && errno == EDOM && availableCalls == 1);
    CHECK(ObserveHttpAvailable((void*)0x5555, NULL) == TRUE);
    CHECK(GetLastError() == 1234 && errno == EDOM && availableCalls == 2);
    DWORD status = 0, length = sizeof(status);
    CHECK(ObserveHttpHeaders((void*)0x5555, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        NULL, &status, &length, NULL) == TRUE && status == 200 && length == sizeof(DWORD));
    CHECK(GetLastError() == 1234 && errno == EDOM && headersCalls == 1);
    failHeaders = true;
    CHECK(ObserveHttpHeaders((void*)0x5555, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        NULL, (void*)0xdead, NULL, NULL) == FALSE);
    CHECK(GetLastError() == ERROR_INSUFFICIENT_BUFFER && errno == EDOM && headersCalls == 2);
    CHECK(ObserveHttpCallback((void*)0x5555, NativeCallback, 0x123, 0) == (WINHTTP_STATUS_CALLBACK)0x7777);
    CHECK(GetLastError() == 1234 && errno == EDOM && callbackCalls == 1 && !badArguments);
    const unsigned long resolves = g_http_resolves.load();
    HMODULE winhttp = GetModuleHandleA("winhttp.dll");
    CHECK(ResolveDynamicProcedure(winhttp, "WinHttpReceiveResponse", (FARPROC)FakeReceive, false) == (FARPROC)ObserveHttpReceive);
    CHECK(g_http_resolves.load() == resolves);
    printf("PASS: dynamic resolver, Winsock ABI, synthetic IAT, HTTP completion preservation; assertions=%u\n", checks);
    return 0;
}
