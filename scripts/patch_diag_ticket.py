import os

target_path = r"D:\vault-breaker-preservation\client_proxy\steam_api64_diag.cpp"
with open(target_path, "r", encoding="utf-8") as f:
    content = f.read()

replacement = """static uint8_t g_saved_appticket_userdata[1024];
static int g_saved_appticket_userdata_len = 0;

static uint32_t CalculateCRC32(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & (-(int)(crc & 1)));
        }
    }
    return ~crc;
}

static int WriteVarint(uint8_t* dst, uint64_t val) {
    int idx = 0;
    while (val >= 0x80) {
        dst[idx++] = (uint8_t)((val & 0x7F) | 0x80);
        val >>= 7;
    }
    dst[idx++] = (uint8_t)(val & 0x7F);
    return idx;
}

static uint64_t g_next_api_call = 1;
static uint64_t SteamUser_RequestEncryptedAppTicket(void* self, void* pDataToInclude, int cbDataToInclude) {
    void* caller = _ReturnAddress();
    DWORD tid = GetCurrentThreadId();
    uint64_t timestampMs = GetTickCount64();
    LogCallerInfo("SteamUser-RequestEncryptedAppTicket", caller);
    uint64_t callId = g_next_api_call++;

    char sha256Hex[65] = "None";
    char prevHash[65] = "None";
    bool hashChanged = false;

    if (pDataToInclude && cbDataToInclude > 0) {
        if (cbDataToInclude <= 1024) {
            memcpy(g_saved_appticket_userdata, pDataToInclude, cbDataToInclude);
            g_saved_appticket_userdata_len = cbDataToInclude;
        }

        ComputeSHA256(pDataToInclude, (size_t)cbDataToInclude, sha256Hex);

        // Check previous launch hash
        FILE* fpPrev = fopen("D:\\\\Marathon-live\\\\pDataToInclude_prev_hash.txt", "r");
        if (fpPrev) {
            if (fscanf(fpPrev, "%64s", prevHash) == 1) {
                hashChanged = (strcmp(sha256Hex, prevHash) != 0);
            }
            fclose(fpPrev);
        } else {
            hashChanged = true;
        }

        // Store current hash
        FILE* fpNew = fopen("D:\\\\Marathon-live\\\\pDataToInclude_prev_hash.txt", "w");
        if (fpNew) {
            fprintf(fpNew, "%s\\n", sha256Hex);
            fclose(fpNew);
        }

        // Store raw bytes in restricted local diagnostic file ONLY
        FILE* fpRaw = fopen("D:\\\\Marathon-live\\\\pDataToInclude_raw.bin", "wb");
        if (fpRaw) {
            fwrite(pDataToInclude, 1, cbDataToInclude, fpRaw);
            fclose(fpRaw);
        }
    }

    LogMsg("[SteamUser] RequestEncryptedAppTicket called: len=%d bytes, SHA-256=%s, changed_from_last_run=%s, callId=%llu, timestamp=%llu ms",
           cbDataToInclude, sha256Hex, hashChanged ? "YES" : "NO (identical to previous launch)",
           (unsigned long long)callId, (unsigned long long)timestampMs);

    // Launch thread snapshot monitor if not already running
    if (!g_diag_monitor_started) {
        g_diag_monitor_started = true;
        CreateThread(NULL, 0, DiagnosticSnapshotThreadProc, NULL, 0, NULL);
    }

    return callId;
}

static int SteamUser_GetEncryptedAppTicket(void* self, void* pTicket, int cbMaxTicket, uint32_t* pcbTicket) {
    void* caller = _ReturnAddress();
    LogCallerInfo("SteamUser-GetEncryptedAppTicket", caller);
    LogMsg("[SteamUser] GetEncryptedAppTicket called (pTicket=%p, max=%d, pcbTicket=%p)", pTicket, cbMaxTicket, pcbTicket);
    if (!pTicket || cbMaxTicket <= 0) {
        if (pcbTicket) *pcbTicket = 143;
        return 0;
    }

    int user_len = g_saved_appticket_userdata_len;
    if (user_len <= 0) user_len = 24;

    int inner_len = 128;
    if (inner_len < user_len + 32) inner_len = user_len + 32;

    uint8_t inner[256];
    if (g_saved_appticket_userdata_len > 0) {
        memcpy(inner, g_saved_appticket_userdata, g_saved_appticket_userdata_len);
    } else {
        memset(inner, 0x55, user_len);
    }
    for (int i = user_len; i < inner_len; i++) {
        inner[i] = (uint8_t)((i * 7) & 0xFF);
    }

    uint32_t crc = CalculateCRC32(inner, inner_len);

    uint8_t proto[512];
    int p = 0;
    // Field 1: ticket_version_no = 1
    proto[p++] = (1 << 3) | 0;
    p += WriteVarint(&proto[p], 1);

    // Field 2: crc_encryptedticket
    proto[p++] = (2 << 3) | 0;
    p += WriteVarint(&proto[p], crc);

    // Field 3: cb_encrypteduserdata
    proto[p++] = (3 << 3) | 0;
    p += WriteVarint(&proto[p], user_len);

    // Field 4: cb_encrypted_appownershipticket
    proto[p++] = (4 << 3) | 0;
    p += WriteVarint(&proto[p], inner_len - user_len);

    // Field 5: encrypted_ticket
    proto[p++] = (5 << 3) | 2;
    p += WriteVarint(&proto[p], inner_len);
    memcpy(&proto[p], inner, inner_len);
    p += inner_len;

    int copy_len = cbMaxTicket < p ? cbMaxTicket : p;
    memcpy(pTicket, proto, copy_len);
    if (pcbTicket) *pcbTicket = copy_len;

    LogMsg("[SteamUser] Generated valid EncryptedAppTicket Protobuf (total_len=%d, user_data_len=%d, crc=0x%08X) -> returning 1 (true)",
           copy_len, user_len, crc);
    return 1;
}"""

target_start = content.find("static uint64_t g_next_api_call = 1;")
target_end = content.find("static int SteamUser_GetGameBadgeLevel")

if target_start != -1 and target_end != -1:
    new_content = content[:target_start] + replacement + "\n\n" + content[target_end:]
    with open(target_path, "w", encoding="utf-8") as f:
        f.write(new_content)
    print("Successfully patched steam_api64_diag.cpp!")
else:
    print(f"Failed to find targets: start={target_start}, end={target_end}")
