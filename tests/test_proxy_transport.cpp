// Exercise the real hook functions as ordinary EXE functions. DllMain is NOT
// executed, no DLL is loaded, no IAT is patched, and every socket call is stubbed.
#if defined(MARATHON_TEST_BASELINE)
#define MARATHON_PROXY_SOURCE "../client_proxy/steam_api64_baseline_14D83586.cpp"
#elif !defined(MARATHON_PROXY_SOURCE)
#define MARATHON_PROXY_SOURCE "../client_proxy/steam_api64.cpp"
#endif
#include MARATHON_PROXY_SOURCE
#include <wchar.h>

static unsigned g_checks = 0;
#define REQUIRE(value) do { ++g_checks; if (!(value)) { \
    fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #value); return 1; } } while (0)

static sockaddr_storage g_observed;
static int g_observed_length;
static unsigned g_socket_calls;
static wchar_t g_observed_host[256];
static INTERNET_PORT g_observed_port;

static int record_address(const sockaddr* address, int length) {
    ++g_socket_calls;
    g_observed_length = length;
    memset(&g_observed, 0, sizeof(g_observed));
    if (address && length >= 0 && length <= (int)sizeof(g_observed))
        memcpy(&g_observed, address, length);
    return 42;
}
static int WSAAPI fake_connect(SOCKET, const sockaddr* address, int length) {
    return record_address(address, length);
}
static int WSAAPI fake_wsa_connect(SOCKET, const sockaddr* address, int length,
                                  LPWSABUF, LPWSABUF, LPQOS, LPQOS) {
    return record_address(address, length);
}
static BOOL PASCAL fake_connect_ex(SOCKET, const sockaddr* address, int length,
                                  PVOID, DWORD, LPDWORD, LPOVERLAPPED) {
    record_address(address, length);
    return TRUE;
}
static HINTERNET WINAPI fake_http_connect(HINTERNET, LPCWSTR host, INTERNET_PORT port, DWORD) {
    wcscpy_s(g_observed_host, host);
    g_observed_port = port;
    return reinterpret_cast<HINTERNET>(0x1234);
}

static int ipv4_case(int hook, const char* host, unsigned short port,
                     const char* expected_host, unsigned short expected_port) {
    sockaddr_in input = {};
    input.sin_family = AF_INET;
    input.sin_port = htons(port);
    REQUIRE(InetPtonA(AF_INET, host, &input.sin_addr) == 1);
    const sockaddr_in original = input;
    g_socket_calls = 0;
    int result = 0;
    if (hook == 0) result = Hook_connect(123, (sockaddr*)&input, sizeof(input));
    if (hook == 1) result = Hook_WSAConnect(123, (sockaddr*)&input, sizeof(input), NULL, NULL, NULL, NULL);
    if (hook == 2) result = Hook_ConnectEx(123, (sockaddr*)&input, sizeof(input), NULL, 0, NULL, NULL);
    REQUIRE(result == (hook == 2 ? TRUE : 42));
    REQUIRE(g_socket_calls == 1);
    REQUIRE(g_observed_length == sizeof(sockaddr_in));
    const sockaddr_in* actual = reinterpret_cast<const sockaddr_in*>(&g_observed);
    IN_ADDR expected = {};
    REQUIRE(InetPtonA(AF_INET, expected_host, &expected) == 1);
    if (ntohs(actual->sin_port) != expected_port)
        fprintf(stderr, "hook=%d input=%s:%u actual_port=%u expected_port=%u\n",
                hook, host, port, ntohs(actual->sin_port), expected_port);
    REQUIRE(ntohs(actual->sin_port) == expected_port);
    REQUIRE(actual->sin_addr.s_addr == expected.s_addr);
    REQUIRE(memcmp(&input, &original, sizeof(input)) == 0);
    return 0;
}

static int ipv6_case(const char* host, unsigned short port,
                     const char* expected_host, unsigned short expected_port) {
    sockaddr_in6 input = {};
    input.sin6_family = AF_INET6;
    input.sin6_port = htons(port);
    REQUIRE(InetPtonA(AF_INET6, host, &input.sin6_addr) == 1);
    const sockaddr_in6 original = input;
    g_socket_calls = 0;
    REQUIRE(Hook_connect(123, (sockaddr*)&input, sizeof(input)) == 42);
    REQUIRE(g_socket_calls == 1);
    const sockaddr_in6* actual = reinterpret_cast<const sockaddr_in6*>(&g_observed);
    IN6_ADDR expected = {};
    REQUIRE(InetPtonA(AF_INET6, expected_host, &expected) == 1);
    REQUIRE(ntohs(actual->sin6_port) == expected_port);
    REQUIRE(memcmp(&actual->sin6_addr, &expected, sizeof(expected)) == 0);
    REQUIRE(memcmp(&input, &original, sizeof(input)) == 0);
    return 0;
}

static int http_case(const wchar_t* host, unsigned short port,
                     const wchar_t* expected_host, unsigned short expected_port) {
    REQUIRE(Hook_WinHttpConnect(NULL, host, port, 0) == reinterpret_cast<HINTERNET>(0x1234));
    REQUIRE(wcscmp(g_observed_host, expected_host) == 0);
    REQUIRE(g_observed_port == expected_port);
    return 0;
}

// Optional end-to-end request through the actual connect hook in this EXE.
// It only uses an already-running loopback server; it never starts one.
static int http_probe() {
    WSADATA data = {};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return 2;
    g_real_connect = ::connect;
    SOCKET socket_value = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_value == INVALID_SOCKET) { WSACleanup(); return 2; }
    DWORD timeout = 3000;
    setsockopt(socket_value, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    sockaddr_in target = {};
    target.sin_family = AF_INET;
    target.sin_port = htons(80);
    InetPtonA(AF_INET, "127.0.0.1", &target.sin_addr);
    int result = 1;
    if (Hook_connect(socket_value, (sockaddr*)&target, sizeof(target)) == 0) {
        const char request[] = "GET /cfg_a/direct_settings/global/global.json HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\nUser-Agent: preservation-native-routing-probe\r\nConnection: close\r\n\r\n";
        int sent = 0;
        while (sent < (int)sizeof(request) - 1) {
            int amount = send(socket_value, request + sent, (int)sizeof(request) - 1 - sent, 0);
            if (amount <= 0) break;
            sent += amount;
        }
        char response[8192] = {};
        int used = 0;
        if (sent == sizeof(request) - 1) {
            while (used < (int)sizeof(response) - 1) {
                int amount = recv(socket_value, response + used, (int)sizeof(response) - 1 - used, 0);
                if (amount <= 0) break;
                used += amount;
            }
            char* header_end = strstr(response, "\r\n\r\n");
            char* length_header = strstr(response, "\r\nContent-Length: ");
            char* length_end = NULL;
            unsigned long body_length = length_header ? strtoul(length_header + 18, &length_end, 10) : 0;
            bool complete = header_end && length_header && length_header < header_end && length_end &&
                strncmp(length_end, "\r\n", 2) == 0 &&
                (unsigned long)(used - (header_end + 4 - response)) == body_length;
            if (complete && (strncmp(response, "HTTP/1.1 200 ", 13) == 0 || strncmp(response, "HTTP/1.0 200 ", 13) == 0)) {
                puts("PASS: plaintext request through native connect hook completed with HTTP 200 and complete body");
                result = 0;
            } else fprintf(stderr, "FAIL: native connect hook did not receive a complete HTTP 200 response (%d bytes)\n", used);
        }
    } else fprintf(stderr, "FAIL: native connect hook failed (%d)\n", WSAGetLastError());
    closesocket(socket_value);
    WSACleanup();
    return result;
}

int main(int argc, char** argv) {
    strcpy_s(g_log_path, "NUL");
    if (argc == 2 && strcmp(argv[1], "--http-probe") == 0) return http_probe();
    g_real_connect = fake_connect;
    g_real_WSAConnect = fake_wsa_connect;
    g_real_ConnectEx = fake_connect_ex;
    g_real_WinHttpConnect = fake_http_connect;
    const unsigned short local_ports[] = {80, 443, 8080, 8081, 7777, 50123};
    for (int hook = 0; hook < 3; ++hook) {
        for (unsigned short port : local_ports) {
            if (ipv4_case(hook, "127.0.0.1", port, "127.0.0.1", port)) return 1;
        }
        if (ipv4_case(hook, "127.3.2.1", 80, "127.3.2.1", 80)) return 1;
        if (ipv4_case(hook, "203.0.113.1", 80, "127.0.0.1", 80)) return 1;
        if (ipv4_case(hook, "203.0.113.1", 443, "127.0.0.1", 8080)) return 1;
        if (ipv4_case(hook, "203.0.113.1", 8080, "127.0.0.1", 8080)) return 1;
        if (ipv4_case(hook, "203.0.113.1", 7777, "127.0.0.1", 7777)) return 1;
        if (ipv4_case(hook, "203.0.113.1", 7505, "127.0.0.1", 7505)) return 1;
        strcpy_s(g_server_port, "8443");
        if (ipv4_case(hook, "203.0.113.1", 443, "127.0.0.1", 8443)) return 1;
        if (ipv4_case(hook, "127.0.0.1", 80, "127.0.0.1", 80)) return 1;
        strcpy_s(g_server_port, "8080");
    }
    if (ipv6_case("::1", 80, "::1", 80)) return 1;
    if (ipv6_case("::1", 443, "::1", 443)) return 1;
    if (ipv6_case("::ffff:127.0.0.1", 80, "::ffff:127.0.0.1", 80)) return 1;
    if (ipv6_case("2001:db8::1", 80, "::1", 80)) return 1;
    if (ipv6_case("2001:db8::1", 443, "::1", 8080)) return 1;
    if (http_case(L"127.0.0.1", 80, L"127.0.0.1", 80)) return 1;
    if (http_case(L"127.3.2.1", 443, L"127.3.2.1", 443)) return 1;
    if (http_case(L"LOCALHOST", 80, L"LOCALHOST", 80)) return 1;
    if (http_case(L"::1", 80, L"::1", 80)) return 1;
    if (http_case(L"content.example.invalid", 80, L"127.0.0.1", 80)) return 1;
    if (http_case(L"content.example.invalid", 443, L"127.0.0.1", 8080)) return 1;
    if (http_case(L"content.example.invalid", 7777, L"127.0.0.1", 7777)) return 1;
    puts("PASS: real connect/WSAConnect/ConnectEx/WinHTTP hooks; no network or DLL loading");
    printf("Assertions: %u\n", g_checks);
    return 0;
}
