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
    restart = steam.SteamAPI_RestartAppIfNecessary(3065800)
    assert restart is False, "Must not request app restart"
    
    # 2. SteamAPI_IsSteamRunning must return 1
    steam.SteamAPI_IsSteamRunning.restype = ctypes.c_bool
    assert steam.SteamAPI_IsSteamRunning() is True
    
    # 3. SteamAPI_Init must return 1
    steam.SteamAPI_Init.restype = ctypes.c_bool
    assert steam.SteamAPI_Init() is True
    
    # 4. SteamInternal_FindOrCreateUserInterface must return valid pointers for all interfaces
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

    p_stats = steam.SteamInternal_FindOrCreateUserInterface(1, b"STEAMUSERSTATS_INTERFACE_VERSION012")
    assert p_stats is not None and p_stats != 0

    p_input = steam.SteamInternal_FindOrCreateUserInterface(1, b"SteamInput006")
    assert p_input is not None and p_input != 0

def test_steam_apps_vtable_calls():
    """Verify ISteamApps008 vtable methods with case-insensitive interface name."""
    steam = ctypes.CDLL(str(PROXY_DLL_PATH))
    steam.SteamInternal_FindOrCreateUserInterface.restype = ctypes.c_void_p
    steam.SteamInternal_FindOrCreateUserInterface.argtypes = [ctypes.c_uint32, ctypes.c_char_p]

    p_apps = steam.SteamInternal_FindOrCreateUserInterface(1, b"STEAMAPPS_INTERFACE_VERSION008")
    vtable_addr = ctypes.c_void_p.from_address(p_apps).value

    # Slot 0: BIsSubscribed -> int (*)(void* self)
    slot0_addr = ctypes.c_void_p.from_address(vtable_addr + 0 * 8).value
    is_sub = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p)(slot0_addr)(p_apps)
    assert is_sub == 1, f"Expected BIsSubscribed == 1, got {is_sub}"

    # Slot 4: GetCurrentGameLanguage -> const char* (*)(void* self)
    slot4_addr = ctypes.c_void_p.from_address(vtable_addr + 4 * 8).value
    lang = ctypes.CFUNCTYPE(ctypes.c_char_p, ctypes.c_void_p)(slot4_addr)(p_apps)
    assert lang == b"english", f"Expected language 'english', got {lang}"

    # Slot 5: GetAvailableGameLanguages -> const char* (*)(void* self)
    slot5_addr = ctypes.c_void_p.from_address(vtable_addr + 5 * 8).value
    avail_langs = ctypes.CFUNCTYPE(ctypes.c_char_p, ctypes.c_void_p)(slot5_addr)(p_apps)
    assert avail_langs == b"english", f"Expected avail_langs 'english', got {avail_langs}"

    # Slot 20: GetAppOwner -> void* (*)(void* self, void* pOut) returning pointer to uint64_t
    slot20_addr = ctypes.c_void_p.from_address(vtable_addr + 20 * 8).value
    get_owner = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)(slot20_addr)
    owner_buf = ctypes.c_uint64(0)
    ret_ptr = get_owner(p_apps, ctypes.byref(owner_buf))
    owner_id = ctypes.c_uint64.from_address(ret_ptr).value
    assert owner_id == 76561198000001001, f"Unexpected owner ID: {owner_id}"
    assert owner_buf.value == 76561198000001001, f"Unexpected buffer owner ID: {owner_buf.value}"

    # Slot 23: GetAppBuildId -> uint32_t (*)(void* self)
    slot23_addr = ctypes.c_void_p.from_address(vtable_addr + 23 * 8).value
    build_id = ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.c_void_p)(slot23_addr)(p_apps)
    assert build_id == 26136895, f"Expected build ID 26136895, got {build_id}"

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
    assert app_id == 3065800, f"Expected AppID 3065800, got {app_id}"
    
    # Slot 4: GetIPCountry -> const char* (*)(void* self)
    slot4_addr = ctypes.c_void_p.from_address(vtable_addr + 4 * 8).value
    get_country = ctypes.CFUNCTYPE(ctypes.c_char_p, ctypes.c_void_p)(slot4_addr)
    country = get_country(p_utils)
    assert country == b"US"

    # Slot 23: GetSteamUILanguage -> const char* (*)(void* self)
    slot23_addr = ctypes.c_void_p.from_address(vtable_addr + 23 * 8).value
    ui_lang = ctypes.CFUNCTYPE(ctypes.c_char_p, ctypes.c_void_p)(slot23_addr)(p_utils)
    assert ui_lang == b"english", f"Expected UI language 'english', got {ui_lang}"

def test_steam_user_vtable_calls():
    """Verify ISteamUser023 vtable methods (SteamID, GetAuthSessionTicket)."""
    steam = ctypes.CDLL(str(PROXY_DLL_PATH))
    steam.SteamInternal_FindOrCreateUserInterface.restype = ctypes.c_void_p
    steam.SteamInternal_FindOrCreateUserInterface.argtypes = [ctypes.c_uint32, ctypes.c_char_p]
    
    p_user = steam.SteamInternal_FindOrCreateUserInterface(1, b"SteamUser023")
    vtable_addr = ctypes.c_void_p.from_address(p_user).value
    
    # Slot 2: GetSteamID -> void* (*)(void* self, void* pOut) returning pointer to uint64_t
    slot2_addr = ctypes.c_void_p.from_address(vtable_addr + 2 * 8).value
    get_steam_id = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)(slot2_addr)
    out_buf = ctypes.c_uint64(0)
    ret_ptr = get_steam_id(p_user, ctypes.byref(out_buf))
    steam_id = ctypes.c_uint64.from_address(ret_ptr).value
    assert steam_id == 76561198000001001, f"Unexpected SteamID: {steam_id}"
    assert out_buf.value == 76561198000001001, f"Unexpected buffer SteamID: {out_buf.value}"
    
    # Verify fallback pointer when pOut is NULL
    ret_fallback = get_steam_id(p_user, None)
    assert ctypes.c_uint64.from_address(ret_fallback).value == 76561198000001001
    
    # Slot 13: GetAuthSessionTicket
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

    # Slot 21: RequestEncryptedAppTicket
    slot21_addr = ctypes.c_void_p.from_address(vtable_addr + 21 * 8).value
    req_ticket = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int)(slot21_addr)
    call_id = req_ticket(p_user, None, 0)
    assert call_id >= 1, f"Expected valid API call handle >= 1, got {call_id}"

    # Slot 22: GetEncryptedAppTicket
    slot22_addr = ctypes.c_void_p.from_address(vtable_addr + 22 * 8).value
    get_enc_ticket = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_uint32))(slot22_addr)
    enc_buf = (ctypes.c_ubyte * 128)()
    enc_size = ctypes.c_uint32(0)
    ok = get_enc_ticket(p_user, ctypes.byref(enc_buf), 128, ctypes.byref(enc_size))
    assert ok == 1, "Expected GetEncryptedAppTicket success"
    assert enc_size.value == 128, f"Expected 128 ticket bytes, got {enc_size.value}"

def test_context_init_callback():
    """Verify SteamInternal_ContextInit invokes callback and returns offset 0x10."""
    steam = ctypes.CDLL(str(PROXY_DLL_PATH))
    steam.SteamInternal_ContextInit.restype = ctypes.c_void_p
    steam.SteamInternal_ContextInit.argtypes = [ctypes.c_void_p]

    cb_called = [False]
    def on_init(ctx_ptr):
        cb_called[0] = True

    CB_FUNC = ctypes.CFUNCTYPE(None, ctypes.c_void_p)
    cb_inst = CB_FUNC(on_init)

    class ContextData(ctypes.Structure):
        _fields_ = [
            ("pFn", ctypes.c_void_p),
            ("counter", ctypes.c_uint64),
            ("dummy_ctx", ctypes.c_uint64 * 4)
        ]

    data = ContextData()
    data.pFn = ctypes.cast(cb_inst, ctypes.c_void_p).value
    data.counter = 0

    ctx_ptr = steam.SteamInternal_ContextInit(ctypes.byref(data))
    assert cb_called[0], "Expected context init callback to be invoked"
    assert data.counter == 1, "Expected counter to be updated"
    assert ctx_ptr == ctypes.addressof(data.dummy_ctx), "Expected return pointer at offset 0x10"

if __name__ == "__main__":
    test_proxy_dll_exports_and_interface_dispatch()
    test_steam_apps_vtable_calls()
    test_steam_utils_vtable_calls()
    test_steam_user_vtable_calls()
    test_context_init_callback()
    print("[+] All steam proxy unit tests PASSED successfully!")
