// Build against both baseline and current source. Operates only on a fake IAT.
#ifdef MARATHON_TEST_BASELINE
#include "../client_proxy/steam_api64_baseline_14D83586.cpp"
#else
#include "../client_proxy/steam_api64.cpp"
#endif
static int UdpProbe(uintptr_t receiveEntry) {
    // Only called after verifying this entry is the real recvfrom export.
    WSADATA data = {};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return 2;
    SOCKET receiver = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    SOCKET sender = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (receiver == INVALID_SOCKET || sender == INVALID_SOCKET) {
        if (receiver != INVALID_SOCKET) closesocket(receiver);
        if (sender != INVALID_SOCKET) closesocket(sender);
        WSACleanup(); return 2;
    }
    sockaddr_in address = {}; address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    DWORD timeout = 1000;
    setsockopt(receiver, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    int result = 1;
    if (bind(receiver, (sockaddr*)&address, sizeof(address)) == 0) {
        int length = sizeof(address);
        if (getsockname(receiver, (sockaddr*)&address, &length) == 0) {
            const char payload[] = "bootstrap-recvfrom-probe";
            if (sendto(sender, payload, sizeof(payload), 0, (sockaddr*)&address, sizeof(address)) == sizeof(payload)) {
                char received[64] = {}; sockaddr_in from = {}; int fromLength = sizeof(from);
                using Receive = int (WSAAPI*)(SOCKET, char*, int, int, sockaddr*, int*);
                int count = ((Receive)receiveEntry)(receiver, received, sizeof(received), 0, (sockaddr*)&from, &fromLength);
                if (count == sizeof(payload) && memcmp(received, payload, sizeof(payload)) == 0) {
                    puts("PASS: complete loopback UDP datagram received through ordinal 17 import slot");
                    result = 0;
                }
            }
        }
    }
    closesocket(receiver); closesocket(sender); WSACleanup();
    return result;
}

int main(int argc, char** argv) {
    strcpy_s(g_log_path, "NUL");
    HMODULE ws = GetModuleHandleA("ws2_32.dll");
    g_real_connect = (connect_t)::GetProcAddress(ws, "connect");
    g_real_WSAConnect = (WSAConnect_t)::GetProcAddress(ws, "WSAConnect");
    g_real_WSAIoctl = (WSAIoctl_t)::GetProcAddress(ws, "WSAIoctl");
    g_real_sendto = (sendto_t)::GetProcAddress(ws, "sendto");
    unsigned char* memory = (unsigned char*)VirtualAlloc(NULL, 0x4000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!memory) return 2;
    auto dos = (IMAGE_DOS_HEADER*)memory; dos->e_magic = IMAGE_DOS_SIGNATURE; dos->e_lfanew = 0x80;
    auto nt = (IMAGE_NT_HEADERS*)(memory + 0x80); nt->Signature = IMAGE_NT_SIGNATURE;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] = {0x1000, 40};
    auto imports = (IMAGE_IMPORT_DESCRIPTOR*)(memory + 0x1000);
    imports[0].Name = 0x1100; strcpy((char*)memory + 0x1100, "WS2_32.dll");
    imports[0].OriginalFirstThunk = 0x1200; imports[0].FirstThunk = 0x1300;
    auto names = (IMAGE_THUNK_DATA*)(memory + 0x1200);
    auto slots = (IMAGE_THUNK_DATA*)(memory + 0x1300);
    FARPROC nativeReceive = ::GetProcAddress(ws, "recvfrom");
    FARPROC ordinal17 = ::GetProcAddress(ws, (LPCSTR)17);
    if (nativeReceive != ordinal17 || !nativeReceive) return 2;
    names[0].u1.Ordinal = IMAGE_ORDINAL_FLAG | 17;
    slots[0].u1.Function = (uintptr_t)nativeReceive;
    HookModuleIAT((HMODULE)memory, "ordinal-regression-fixture");
    const bool unchanged = slots[0].u1.Function == (uintptr_t)nativeReceive;
    const uintptr_t receiveEntry = slots[0].u1.Function;
    VirtualFree(memory, 0, MEM_RELEASE);
    if (!unchanged) {
        fprintf(stderr, "FAIL: Winsock recvfrom ordinal 17 was replaced by a different API\n");
        return 1;
    }
    puts("PASS: Winsock recvfrom ordinal 17 retains its native receive function");
    if (argc == 2 && strcmp(argv[1], "--udp-probe") == 0) return UdpProbe(receiveEntry);
    return 0;
}
