"""Unit tests verifying compiled steam_api64.dll proxy functionality via ctypes."""
import ctypes
from pathlib import Path

PROXY_DLL_PATH = Path("D:/vault-breaker-preservation/client_proxy/steam_api64.dll")

def test_proxy_dll_exports_and_interface_dispatch():
    assert PROXY_DLL_PATH.exists(), f"Missing proxy DLL at {PROXY_DLL_PATH}"
    
    steam = ctypes.CDLL(str(PROXY_DLL_PATH))
    
    # 1. SteamAPI_RestartAppIfNecessary must return 0 (no restart needed)
    steam.SteamAPI_RestartAppIfNecessary.restype = ctypes.c_bool
    steam.SteamAPI_RestartAppIfNecessary.argtypes = [ctypes.c_uint32]
    restart = steam.SteamAPI_RestartAppIfNecessary(26136895)
    assert restart is False, "Must not request app restart"
    
    # 2. SteamAPI_IsSteamRunning must return 1
    steam.SteamAPI_IsSteamRunning.restype = ctypes.c_bool
    assert steam.SteamAPI_IsSteamRunning() is True
    
    # 3. SteamAPI_Init must return 1
    steam.SteamAPI_Init.restype = ctypes.c_bool
    assert steam.SteamAPI_Init() is True
    
    # 4. SteamInternal_FindOrCreateUserInterface must return valid pointers
    steam.SteamInternal_FindOrCreateUserInterface.restype = ctypes.c_void_p
    steam.SteamInternal_FindOrCreateUserInterface.argtypes = [ctypes.c_uint32, ctypes.c_char_p]
    
    p_user = steam.SteamInternal_FindOrCreateUserInterface(1, b"SteamUser023")
    assert p_user is not None and p_user != 0
    
    p_utils = steam.SteamInternal_FindOrCreateUserInterface(1, b"SteamUtils010")
    assert p_utils is not None and p_utils != 0
    
    p_apps = steam.SteamInternal_FindOrCreateUserInterface(1, b"STEAMAPPS_INTERFACE_VERSION008")
    assert p_apps is not None and p_apps != 0
    
    p_friends = steam.SteamInternal_FindOrCreateUserInterface(1, b"SteamFriends017")
    assert p_friends is not None and p_friends != 0

def test_steam_utils_vtable_calls():
    """Verify ISteamUtils010 vtable methods (AppID, Country, etc.)."""
    steam = ctypes.CDLL(str(PROXY_DLL_PATH))
    steam.SteamInternal_FindOrCreateUserInterface.restype = ctypes.c_void_p
    steam.SteamInternal_FindOrCreateUserInterface.argtypes = [ctypes.c_uint32, ctypes.c_char_p]
    
    p_utils = steam.SteamInternal_FindOrCreateUserInterface(1, b"SteamUtils010")
    vtable_addr = ctypes.c_void_p.from_address(p_utils).value
    
    # Slot 9: GetAppID -> uint32_t (*)(void* self)
    slot9_addr = ctypes.c_void_p.from_address(vtable_addr + 9 * 8).value
    get_app_id = ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.c_void_p)(slot9_addr)
    app_id = get_app_id(p_utils)
    assert app_id == 26136895, f"Expected AppID 26136895, got {app_id}"
    
    # Slot 4: GetIPCountry -> const char* (*)(void* self)
    slot4_addr = ctypes.c_void_p.from_address(vtable_addr + 4 * 8).value
    get_country = ctypes.CFUNCTYPE(ctypes.c_char_p, ctypes.c_void_p)(slot4_addr)
    country = get_country(p_utils)
    assert country == b"US"

def test_steam_user_vtable_calls():
    """Verify ISteamUser023 vtable methods (SteamID, GetAuthSessionTicket)."""
    steam = ctypes.CDLL(str(PROXY_DLL_PATH))
    steam.SteamInternal_FindOrCreateUserInterface.restype = ctypes.c_void_p
    steam.SteamInternal_FindOrCreateUserInterface.argtypes = [ctypes.c_uint32, ctypes.c_char_p]
    
    p_user = steam.SteamInternal_FindOrCreateUserInterface(1, b"SteamUser023")
    vtable_addr = ctypes.c_void_p.from_address(p_user).value
    
    # Slot 2: GetSteamID -> uint64_t (*)(void* self)
    slot2_addr = ctypes.c_void_p.from_address(vtable_addr + 2 * 8).value
    get_steam_id = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p)(slot2_addr)
    steam_id = get_steam_id(p_user)
    assert steam_id == 76561198000001001, f"Unexpected SteamID: {steam_id}"
    
    # Slot 13: GetAuthSessionTicket -> uint32_t (*)(void* self, void* pTicket, int cbMax, uint32_t* pcbTicket, void* pNetId)
    slot13_addr = ctypes.c_void_p.from_address(vtable_addr + 13 * 8).value
    get_ticket = ctypes.CFUNCTYPE(
        ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int,
        ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p
    )(slot13_addr)
    
    ticket_buf = (ctypes.c_ubyte * 128)()
    ticket_size = ctypes.c_uint32(0)
    ticket_handle = get_ticket(p_user, ctypes.byref(ticket_buf), 128, ctypes.byref(ticket_size), None)
    
    assert ticket_handle == 1, "Expected valid ticket handle 1"
    assert ticket_size.value == 128, f"Expected 128 ticket bytes, got {ticket_size.value}"
    assert bytes(ticket_buf)[0] == 0x55, "Unexpected ticket header byte"
