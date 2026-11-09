with open(r"D:\vault-breaker-preservation\client_proxy\steam_api64.cpp", "r", encoding="utf-8") as f:
    content = f.read()

# 1. Add SteamUser_UserHasLicenseForApp
if "SteamUser_UserHasLicenseForApp" not in content:
    target1 = 'static void* SteamUser_GetSteamID(void* self, void* pOutResult) {\n'
    # Find the end of SteamUser_GetSteamID
    pos1 = content.find("return &g_steam_id_storage;\n}")
    if pos1 != -1:
        insert1 = """return &g_steam_id_storage;
}
static int SteamUser_UserHasLicenseForApp(void* self, uint64_t steamID, uint32_t appID) {
    LogMsg("[SteamUser] UserHasLicenseForApp(self=%p, steamID=%llu, appID=%u) called -> 0 (HasLicense)", self, steamID, appID);
    return 0; // k_EUserHasLicenseResultHasLicense = 0
}"""
        content = content[:pos1] + insert1 + content[pos1 + len("return &g_steam_id_storage;\n}"):]
        print("[+] Added SteamUser_UserHasLicenseForApp")

# 2. Add g_user_vtable[12] and g_user_vtable[14]
target2 = "g_user_vtable[2] = (void*)SteamUser_GetSteamID;\n"
if target2 in content and "g_user_vtable[12]" not in content:
    replacement2 = """g_user_vtable[2] = (void*)SteamUser_GetSteamID;
    g_user_vtable[12] = (void*)SteamUser_UserHasLicenseForApp;
    g_user_vtable[14] = (void*)SteamUser_GetAuthSessionTicket;
"""
    content = content.replace(target2, replacement2)
    print("[+] Added g_user_vtable[12] and [14]")

# 3. Fix Hook_CertVerifyCertificateChainPolicy to explicitly return TRUE
old_ssl = """        LogMsg("[Crypto] CertVerifyCertificateChainPolicy (SSL) -> Forcing SUCCESS");
    }
    return res;"""
new_ssl = """        LogMsg("[Crypto] CertVerifyCertificateChainPolicy (SSL) -> Forcing SUCCESS");
        return TRUE;
    }
    return res;"""
if old_ssl in content:
    content = content.replace(old_ssl, new_ssl)
    print("[+] Fixed Hook_CertVerifyCertificateChainPolicy return TRUE")

# 4. Add _ReturnAddress() to SteamAPI_Shutdown
old_shut = """__declspec(dllexport) void __cdecl SteamAPI_Shutdown() {
    LogMsg("[SteamAPI] SteamAPI_Shutdown called");
}"""
new_shut = """__declspec(dllexport) void __cdecl SteamAPI_Shutdown() {
    void* caller = _ReturnAddress();
    LogMsg("[SteamAPI] SteamAPI_Shutdown called by %p", caller);
}"""
if old_shut in content:
    content = content.replace(old_shut, new_shut)
    print("[+] Added caller logging to SteamAPI_Shutdown")

# 5. Add callbacks 163, 331, 336, 704 to SteamAPI_RunCallbacks
old_cb = """        } else if (id == 304) { // AvatarImageLoaded_t
            LogMsg("[SteamAPI] Dispatching callback 304 (AvatarImageLoaded_t) to %p", pCb);
            struct {
                uint64_t steamID;
                int image;
                int wide;
                int tall;
            } avatar = { g_steam_id, 1, 64, 64 };
            runFn(pCb, &avatar, 0, 0);
            g_callbacks[i].dispatched = true;
        }"""

new_cb = """        } else if (id == 304) { // AvatarImageLoaded_t
            LogMsg("[SteamAPI] Dispatching callback 304 (AvatarImageLoaded_t) to %p", pCb);
            struct {
                uint64_t steamID;
                int image;
                int wide;
                int tall;
            } avatar = { g_steam_id, 1, 64, 64 };
            runFn(pCb, &avatar, 0, 0);
            g_callbacks[i].dispatched = true;
        } else if (id == 163) { // GetAuthSessionTicketResponse_t
            LogMsg("[SteamAPI] Dispatching callback 163 (GetAuthSessionTicketResponse_t) to %p", pCb);
            struct {
                uint32_t m_hAuthTicket;
                int m_eResult;
            } authResp = { 1, 1 }; // ticket handle 1, k_EResultOK = 1
            runFn(pCb, &authResp, 0, 0);
            g_callbacks[i].dispatched = true;
        } else if (id == 331) { // PersonaStateChange_t
            LogMsg("[SteamAPI] Dispatching callback 331 (PersonaStateChange_t) to %p", pCb);
            struct {
                uint64_t steamID;
                int changeFlags;
            } persona = { g_steam_id, 0x0001 };
            runFn(pCb, &persona, 0, 0);
            g_callbacks[i].dispatched = true;
        } else if (id == 336) { // FriendRichPresenceUpdate_t
            LogMsg("[SteamAPI] Dispatching callback 336 (FriendRichPresenceUpdate_t) to %p", pCb);
            struct {
                uint64_t steamID;
                uint32_t appID;
            } rich = { g_steam_id, g_app_id };
            runFn(pCb, &rich, 0, 0);
            g_callbacks[i].dispatched = true;
        } else if (id == 704) { // MicroTxnAuthorizationResponse_t
            LogMsg("[SteamAPI] Dispatching callback 704 (MicroTxnAuthorizationResponse_t) to %p", pCb);
            struct {
                uint32_t m_unAppID;
                uint64_t m_ulOrderID;
                uint8_t m_bAuthorized;
            } micro = { g_app_id, 0, 1 };
            runFn(pCb, &micro, 0, 0);
            g_callbacks[i].dispatched = true;
        }"""
if old_cb in content:
    content = content.replace(old_cb, new_cb)
    print("[+] Added callbacks 163, 331, 336, 704")

# 6. CallResult dispatch layout
old_cr = """        LogMsg("[SteamAPI] Dispatching CallResult %llu (EncryptedAppTicketResponse_t: k_EResultOK) to %p", callId, pCb);
        struct {
            int m_eResult;
        } resp = { 1 }; // 1 = k_EResultOK
        runFn(pCb, &resp, 0, callId);"""

new_cr = """        LogMsg("[SteamAPI] Dispatching CallResult %llu (Dual Auth/Encrypted Ticket: k_EResultOK) to %p", callId, pCb);
        struct {
            uint32_t m_hAuthTicket;
            int m_eResult;
        } resp = { 1, 1 }; // ticket handle 1, k_EResultOK = 1 (valid for both 154 and 163)
        runFn(pCb, &resp, 0, callId);"""
if old_cr in content:
    content = content.replace(old_cr, new_cr)
    print("[+] Upgraded CallResult dispatch to dual auth struct")

with open(r"D:\vault-breaker-preservation\client_proxy\steam_api64.cpp", "w", encoding="utf-8") as f:
    f.write(content)
print("[+] Successfully wrote patched steam_api64.cpp!")
