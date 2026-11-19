#pragma once
#include <stddef.h>

// Included after the socket/WinHTTP hooks. All observers call the original
// exactly once and leave application-owned buffers, callbacks and state alone.
struct HttpNativeErrors {
    DWORD win32 = GetLastError();
    int crt = errno;
    ~HttpNativeErrors() { errno = crt; SetLastError(win32); }
};

struct SocketBinding { void* hook; const char* name; };
static SocketBinding SocketObservationBinding(FARPROC original) {
    if (!original) return {NULL, NULL};
#define SOCKET_BIND(real, replacement, label) if (original == (FARPROC)(real) && (real)) return {(void*)(replacement), label}
    SOCKET_BIND(g_real_connect, Hook_connect, "connect");
    SOCKET_BIND(g_real_WSAConnect, Hook_WSAConnect, "WSAConnect");
    SOCKET_BIND(g_real_WSAIoctl, Hook_WSAIoctl, "WSAIoctl");
    SOCKET_BIND(g_real_sendto, Hook_sendto, "sendto");
    SOCKET_BIND(g_real_WSASendTo, Hook_WSASendTo, "WSASendTo");
    SOCKET_BIND(g_real_getaddrinfo, Hook_getaddrinfo, "getaddrinfo");
    SOCKET_BIND(g_real_GetAddrInfoW, Hook_GetAddrInfoW, "GetAddrInfoW");
    SOCKET_BIND(g_real_GetAddrInfoExW, Hook_GetAddrInfoExW, "GetAddrInfoExW");
    SOCKET_BIND(g_real_gethostbyname, Hook_gethostbyname, "gethostbyname");
#undef SOCKET_BIND
    return {NULL, NULL};
}

using CurlEasyPerform = int (__cdecl*)(void*);
using CurlMultiAdd = int (__cdecl*)(void*, void*);
using CurlGetInfo = int (__cdecl*)(void*, int, ...);
using CurlMultiPerform = int (__cdecl*)(void*, int*);
using CurlSocketAction = int (__cdecl*)(void*, SOCKET, int, int*);
struct CurlMessage {
    int type;
    void* easy;
    union { void* pointer; int result; } data;
};
static_assert(offsetof(CurlMessage, easy) == 8 && offsetof(CurlMessage, data) == 16 && sizeof(CurlMessage) == 24);
static_assert(sizeof(long) == 4, "curl response codes use the Windows long ABI");
using CurlMultiRead = CurlMessage* (__cdecl*)(void*, int*);
static std::atomic<CurlEasyPerform> g_curl_perform{nullptr};
static std::atomic<CurlMultiAdd> g_curl_add{nullptr};
static std::atomic<CurlMultiRead> g_curl_read{nullptr};
static std::atomic<CurlGetInfo> g_curl_info{nullptr};
static std::atomic<CurlMultiPerform> g_curl_multi_perform{nullptr};
static std::atomic<CurlSocketAction> g_curl_socket_action{nullptr};
static std::atomic<HMODULE> g_observed_curl_module{nullptr};
static std::atomic<unsigned long> g_http_resolves{0}, g_http_performs{0}, g_http_adds{0}, g_http_done{0}, g_http_win_sends{0};
static std::atomic<unsigned long> g_http_pumps{0}, g_http_socket_actions{0};

static void HttpRouteForLog(const char* url, char* out, size_t capacity) {
    if (!capacity) return;
    out[0] = 0;
    if (!url) return;
    size_t length = 0;
    while (length + 1 < capacity && url[length] && url[length] != '?' && url[length] != '#') ++length;
    const char* scheme = strstr(url, "://");
    if (scheme && scheme < url + length) {
        const char* authority = scheme + 3;
        const char* end = authority + strcspn(authority, "/?#");
        if (memchr(authority, '@', end - authority)) {
            strncpy_s(out, capacity, "<userinfo-url-redacted>", _TRUNCATE);
            return;
        }
    }
    memcpy(out, url, length); out[length] = 0;
}

static void LogCurlResult(const char* stage, void* easy, int result) {
    CurlGetInfo info = g_curl_info.load(std::memory_order_acquire);
    char* url = NULL; long status = 0;
    const int urlResult = info ? info(easy, 0x100001, &url) : -1;
    const int statusResult = info ? info(easy, 0x200002, &status) : -1;
    char route[256] = {};
    if (urlResult == 0) HttpRouteForLog(url, route, sizeof(route));
    LogMsg("[HTTPTrace] %s easy=%p curl_result=%d http_status=%ld status_info_result=%d url_info_result=%d route='%s'",
           stage, easy, result, statusResult == 0 ? status : 0, statusResult, urlResult, route);
}

static __declspec(noinline) int __cdecl ObserveCurlPerform(void* easy) {
    ++g_http_performs;
    {
        HttpNativeErrors incoming;
        LogCallerInfo("HTTPTrace curl_easy_perform", _ReturnAddress());
        LogMsg("[HTTPTrace] easy_perform_begin easy=%p", easy);
    }
    const CurlEasyPerform original = g_curl_perform.load(std::memory_order_acquire);
    const int result = original ? original(easy) : 2;
    HttpNativeErrors errors;
    LogCurlResult("easy_perform_return", easy, result);
    return result;
}

static __declspec(noinline) int __cdecl ObserveCurlAdd(void* multi, void* easy) {
    ++g_http_adds;
    { HttpNativeErrors incoming; LogCallerInfo("HTTPTrace curl_multi_add_handle", _ReturnAddress()); }
    const CurlMultiAdd original = g_curl_add.load(std::memory_order_acquire);
    const int result = original ? original(multi, easy) : 1;
    HttpNativeErrors errors;
    LogMsg("[HTTPTrace] multi_add_return multi=%p easy=%p result=%d", multi, easy, result);
    return result;
}

static __declspec(noinline) CurlMessage* __cdecl ObserveCurlRead(void* multi, int* queued) {
    const CurlMultiRead original = g_curl_read.load(std::memory_order_acquire);
    CurlMessage* message = original ? original(multi, queued) : NULL; // Never drain a second message.
    HttpNativeErrors errors;
    if (message) {
        LogMsg("[HTTPTrace] multi_message multi=%p message=%p type=%d easy=%p", multi, message, message->type, message->easy);
        if (message->type == 1) {
            ++g_http_done;
            LogCallerInfo("HTTPTrace curl_multi_info_read DONE", _ReturnAddress());
            LogCurlResult("multi_done", message->easy, message->data.result);
        }
    }
    return message;
}

static __declspec(noinline) int __cdecl ObserveCurlMultiPerform(void* multi, int* running) {
    CurlMultiPerform original = g_curl_multi_perform.load(std::memory_order_acquire);
    const int result = original ? original(multi, running) : 1;
    HttpNativeErrors errors;
    const unsigned long count = ++g_http_pumps;
    if (count <= 4 || count % 4096 == 0) {
        LogCallerInfo("HTTPTrace curl_multi_perform", _ReturnAddress());
        LogMsg("[HTTPTrace] multi_perform_return multi=%p result=%d running=%d samples=%lu",
               multi, result, result == 0 && running ? *running : -1, count);
    }
    return result;
}
static __declspec(noinline) int __cdecl ObserveCurlSocketAction(void* multi, SOCKET socket, int events, int* running) {
    CurlSocketAction original = g_curl_socket_action.load(std::memory_order_acquire);
    const int result = original ? original(multi, socket, events, running) : 1;
    HttpNativeErrors errors;
    const unsigned long count = ++g_http_socket_actions;
    if (count <= 4 || count % 4096 == 0) {
        LogCallerInfo("HTTPTrace curl_multi_socket_action", _ReturnAddress());
        LogMsg("[HTTPTrace] multi_socket_action_return multi=%p socket=%llu events=%d result=%d running=%d samples=%lu",
               multi, (unsigned long long)socket, events, result, result == 0 && running ? *running : -1, count);
    }
    return result;
}

using HttpSend = BOOL (WINAPI*)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
using HttpReceive = BOOL (WINAPI*)(HINTERNET, LPVOID);
static std::atomic<HttpSend> g_http_send{nullptr};
static std::atomic<HttpReceive> g_http_receive{nullptr};
using HttpRead = BOOL (WINAPI*)(HINTERNET, LPVOID, DWORD, LPDWORD);
using HttpAvailable = BOOL (WINAPI*)(HINTERNET, LPDWORD);
using HttpHeaders = BOOL (WINAPI*)(HINTERNET, DWORD, LPCWSTR, LPVOID, LPDWORD, LPDWORD);
using HttpCallback = WINHTTP_STATUS_CALLBACK (WINAPI*)(HINTERNET, WINHTTP_STATUS_CALLBACK, DWORD, DWORD_PTR);
static std::atomic<HttpRead> g_http_read{nullptr};
static std::atomic<HttpAvailable> g_http_available{nullptr};
static std::atomic<HttpHeaders> g_http_headers{nullptr};
static std::atomic<HttpCallback> g_http_callback{nullptr};
static __declspec(noinline) BOOL WINAPI ObserveHttpSend(HINTERNET request, LPCWSTR headers, DWORD headerLength,
    LPVOID body, DWORD bodyLength, DWORD total, DWORD_PTR context) {
    ++g_http_win_sends;
    { HttpNativeErrors incoming; LogCallerInfo("HTTPTrace WinHttpSendRequest", _ReturnAddress()); }
    const HttpSend original = g_http_send.load(std::memory_order_acquire);
    const BOOL result = original ? original(request, headers, headerLength, body, bodyLength, total, context) : FALSE;
    HttpNativeErrors errors;
    LogMsg("[HTTPTrace] winhttp_send_return request=%p result=%d error=%lu body_bytes=%lu total_bytes=%lu completion=not_asserted",
           request, result, errors.win32, bodyLength, total);
    return result;
}
static __declspec(noinline) BOOL WINAPI ObserveHttpReceive(HINTERNET request, LPVOID reserved) {
    const HttpReceive original = g_http_receive.load(std::memory_order_acquire);
    const BOOL result = original ? original(request, reserved) : FALSE;
    HttpNativeErrors errors;
    LogCallerInfo("HTTPTrace WinHttpReceiveResponse", _ReturnAddress());
    LogMsg("[HTTPTrace] winhttp_receive_return request=%p result=%d error=%lu async_callback=unmodified completion=not_asserted",
           request, result, errors.win32);
    return result;
}

static __declspec(noinline) BOOL WINAPI ObserveHttpRead(HINTERNET request, LPVOID buffer, DWORD count, LPDWORD read) {
    const HttpRead original = g_http_read.load(std::memory_order_acquire);
    const BOOL result = original ? original(request, buffer, count, read) : FALSE;
    HttpNativeErrors errors;
    LogCallerInfo("HTTPTrace WinHttpReadData", _ReturnAddress());
    LogMsg("[HTTPTrace] winhttp_read_return request=%p result=%d error=%lu requested=%lu output_pointer=%p reported_bytes=%lu completion=not_asserted",
           request, result, errors.win32, count, read, result && read ? *read : 0);
    return result;
}
static __declspec(noinline) BOOL WINAPI ObserveHttpAvailable(HINTERNET request, LPDWORD available) {
    const HttpAvailable original = g_http_available.load(std::memory_order_acquire);
    const BOOL result = original ? original(request, available) : FALSE;
    HttpNativeErrors errors;
    LogMsg("[HTTPTrace] winhttp_available_return request=%p result=%d error=%lu output_pointer=%p reported_bytes=%lu completion=not_asserted",
           request, result, errors.win32, available, result && available ? *available : 0);
    return result;
}
static __declspec(noinline) BOOL WINAPI ObserveHttpHeaders(HINTERNET request, DWORD level, LPCWSTR name,
                                                         LPVOID buffer, LPDWORD length, LPDWORD index) {
    const HttpHeaders original = g_http_headers.load(std::memory_order_acquire);
    const BOOL result = original ? original(request, level, name, buffer, length, index) : FALSE;
    HttpNativeErrors errors;
    DWORD status = 0;
    const bool numericStatus = (level & 0xffff) == WINHTTP_QUERY_STATUS_CODE &&
        (level & WINHTTP_QUERY_FLAG_NUMBER) && !(level & WINHTTP_QUERY_FLAG_REQUEST_HEADERS);
    const bool statusValid = result && numericStatus && buffer && length && *length >= sizeof(DWORD);
    if (statusValid) memcpy(&status, buffer, sizeof(status));
    LogCallerInfo("HTTPTrace WinHttpQueryHeaders", _ReturnAddress());
    LogMsg("[HTTPTrace] winhttp_headers_return request=%p result=%d error=%lu level=0x%lx numeric_status_valid=%d http_status=%lu",
           request, result, errors.win32, level, statusValid, status);
    return result;
}
static __declspec(noinline) WINHTTP_STATUS_CALLBACK WINAPI ObserveHttpCallback(HINTERNET handle,
    WINHTTP_STATUS_CALLBACK callback, DWORD flags, DWORD_PTR reserved) {
    const HttpCallback original = g_http_callback.load(std::memory_order_acquire);
    WINHTTP_STATUS_CALLBACK previous = original ? original(handle, callback, flags, reserved) : WINHTTP_INVALID_STATUS_CALLBACK;
    HttpNativeErrors errors;
    LogCallerInfo("HTTPTrace WinHttpSetStatusCallback", _ReturnAddress());
    if (callback && callback != WINHTTP_INVALID_STATUS_CALLBACK)
        LogCallerInfo("HTTPTrace native_status_callback", (void*)callback);
    LogMsg("[HTTPTrace] winhttp_callback_return handle=%p callback=%p flags=0x%lx previous=%p error=%lu callback=unmodified",
           handle, callback, flags, previous, errors.win32);
    return previous;
}

static bool HttpSymbolIs(LPCSTR name, const char* text, unsigned ordinal) {
    return (uintptr_t)name <= 65535 ? (uintptr_t)name == ordinal : strcmp(name, text) == 0;
}
template<class Function> static bool PublishHttpOriginal(std::atomic<Function>& slot, FARPROC original) {
    Function expected = nullptr;
    const Function value = reinterpret_cast<Function>(original);
    return slot.compare_exchange_strong(expected, value, std::memory_order_release) || expected == value;
}

static FARPROC ResolveDynamicProcedure(HMODULE module, LPCSTR name, FARPROC original, bool logResolution) {
    if (!module || !name || !original) return original;
    HttpNativeErrors errors;
    char path[MAX_PATH] = {};
    if (!GetModuleFileNameA(module, path, sizeof(path))) return original;
    const char* slash = strrchr(path, '\\');
    const char* base = slash ? slash + 1 : path;
    const bool named = (uintptr_t)name > 65535;
    char ordinal[24] = {};
    if (!named) snprintf(ordinal, sizeof(ordinal), "#%u", (unsigned)(uintptr_t)name);
    const char* label = named ? name : ordinal;
    FARPROC replacement = original;
    if (_stricmp(base, "ws2_32.dll") == 0) {
        SocketBinding binding = SocketObservationBinding(original);
        if (binding.hook) replacement = (FARPROC)binding.hook;
    } else if (_stricmp(base, "kernel32.dll") == 0 || _stricmp(base, "kernelbase.dll") == 0) {
        if (named && strcmp(name, "GetProcAddress") == 0) replacement = (FARPROC)Hook_GetProcAddress;
    } else if (_stricmp(base, "crypt32.dll") == 0) {
        if (named && strcmp(name, "CertVerifyCertificateChainPolicy") == 0) replacement = (FARPROC)Hook_CertVerifyCertificateChainPolicy;
    } else if (_stricmp(base, "winhttp.dll") == 0 && named) {
        if (strcmp(name, "WinHttpConnect") == 0) replacement = (FARPROC)Hook_WinHttpConnect;
        if (strcmp(name, "WinHttpOpenRequest") == 0) replacement = (FARPROC)Hook_WinHttpOpenRequest;
        if (strcmp(name, "WinHttpSendRequest") == 0 && PublishHttpOriginal(g_http_send, original)) replacement = (FARPROC)ObserveHttpSend;
        if (strcmp(name, "WinHttpReceiveResponse") == 0 && PublishHttpOriginal(g_http_receive, original)) replacement = (FARPROC)ObserveHttpReceive;
        if (strcmp(name, "WinHttpReadData") == 0 && PublishHttpOriginal(g_http_read, original)) replacement = (FARPROC)ObserveHttpRead;
        if (strcmp(name, "WinHttpQueryDataAvailable") == 0 && PublishHttpOriginal(g_http_available, original)) replacement = (FARPROC)ObserveHttpAvailable;
        if (strcmp(name, "WinHttpQueryHeaders") == 0 && PublishHttpOriginal(g_http_headers, original)) replacement = (FARPROC)ObserveHttpHeaders;
        if (strcmp(name, "WinHttpSetStatusCallback") == 0 && PublishHttpOriginal(g_http_callback, original)) replacement = (FARPROC)ObserveHttpCallback;
    } else if (_stricmp(base, "libcurl.dll") == 0) {
        HMODULE expected = nullptr;
        if (!g_observed_curl_module.compare_exchange_strong(expected, module) && expected != module) {
            LogMsg("[HTTPTrace] resolve module='%s' export='%s' observed=0 reason=multiple_curl_modules", base, label);
            return original;
        }
        // Pinned supplied 8.11.1-DEV export RVAs. Do not assume another DLL's
        // ordinal/layout is compatible; pass it through and log the mismatch.
        const uintptr_t rva = (uintptr_t)original - (uintptr_t)module;
        FARPROC info = ::GetProcAddress(module, "curl_easy_getinfo");
        if ((uintptr_t)info == (uintptr_t)module + 0x18770) PublishHttpOriginal(g_curl_info, info);
        if (HttpSymbolIs(name, "curl_easy_perform", 12) && rva == 0x18990 && PublishHttpOriginal(g_curl_perform, original)) replacement = (FARPROC)ObserveCurlPerform;
        if (HttpSymbolIs(name, "curl_multi_add_handle", 49) && rva == 0x38210 && PublishHttpOriginal(g_curl_add, original)) replacement = (FARPROC)ObserveCurlAdd;
        if (HttpSymbolIs(name, "curl_multi_info_read", 54) && rva == 0x38830 && PublishHttpOriginal(g_curl_read, original)) replacement = (FARPROC)ObserveCurlRead;
        if (HttpSymbolIs(name, "curl_multi_perform", 56) && rva == 0x38a90 && PublishHttpOriginal(g_curl_multi_perform, original)) replacement = (FARPROC)ObserveCurlMultiPerform;
        if (HttpSymbolIs(name, "curl_multi_socket_action", 61) && rva == 0x39040 && PublishHttpOriginal(g_curl_socket_action, original)) replacement = (FARPROC)ObserveCurlSocketAction;
        // No variadic curl_easy_setopt interception: preserve its ABI unchanged.
    } else return original;
    if (logResolution) {
        ++g_http_resolves;
        LogMsg("[HTTPTrace] resolve module='%s' export='%s' original=%p returned=%p observed=%d", base, label, original, replacement, replacement != original);
    }
    return replacement;
}
