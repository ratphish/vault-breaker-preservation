import ctypes

ctypes.windll.kernel32.SetDllDirectoryA(b'C:\\Program Files (x86)\\Steam')
h = ctypes.windll.kernel32.LoadLibraryA(b'C:\\Program Files (x86)\\Steam\\steamclient64.dll')

Steam_CreateSteamPipe = ctypes.CFUNCTYPE(ctypes.c_int32)(ctypes.windll.kernel32.GetProcAddress(h, b'Steam_CreateSteamPipe'))
Steam_ConnectToGlobalUser = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_int32)(ctypes.windll.kernel32.GetProcAddress(h, b'Steam_ConnectToGlobalUser'))
CreateInterface = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int32))(ctypes.windll.kernel32.GetProcAddress(h, b'CreateInterface'))

pipe = Steam_CreateSteamPipe()
print(f"SteamPipe: {pipe}")
user = Steam_ConnectToGlobalUser(pipe)
print(f"SteamUser: {user}")

err = ctypes.c_int32(0)
pUtils = CreateInterface(b"SteamNetworkingUtils004", ctypes.byref(err))
print(f"SteamNetworkingUtils004: {hex(pUtils) if pUtils else 'NULL'}, err: {err.value}")

if pUtils:
    vtable = ctypes.cast(pUtils, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
    fn_ptr = vtable[1]
    print(f"GetRelayNetworkStatus fn: {hex(fn_ptr)}")
    
    class SteamRelayNetworkStatus_t(ctypes.Structure):
        _fields_ = [
            ("m_eAvail", ctypes.c_int32),
            ("m_bPingMeasurementInProgress", ctypes.c_int32),
            ("m_eAvailNetworkConfig", ctypes.c_int32),
            ("m_eAvailAnyRelay", ctypes.c_int32),
            ("m_szDebugMsg", ctypes.c_char * 256)
        ]
    status = SteamRelayNetworkStatus_t()
    fn = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_void_p, ctypes.POINTER(SteamRelayNetworkStatus_t))(fn_ptr)
    ret = fn(pUtils, ctypes.byref(status))
    print(f"Relay Status Result (m_eAvail): {ret}")
    print(f"  m_bPingMeasurementInProgress: {status.m_bPingMeasurementInProgress}")
    print(f"  m_eAvailNetworkConfig: {status.m_eAvailNetworkConfig}")
    print(f"  m_eAvailAnyRelay: {status.m_eAvailAnyRelay}")
    print(f"  m_szDebugMsg: {status.m_szDebugMsg.decode('latin1', errors='ignore')}")
