# Marathon Vault Breaker Preservation — BAP Service 305 Live Integration Test Report

**Execution Date:** 2026-11-19 22:22:00 – 22:23:05 EST  
**Target Build:** Bungie *Marathon* Retail RC `248199.26.10.21.2300.gol_retail.rc` (Steam Build `26136895`, Steam AppID `3065800`)  
**Target Preserved Activity:** Cryo Archive — **Vault Breaker**  
**Host Environment:** Windows 11 x64, DirectX 12  
**Firewall Isolation:** Outbound block rule `MarathonPreservation248199RetailPackages` enforced on `D:\Marathon-preservation\client-248199-retail-packages\Marathon.exe`  
**Repository Working Directory:** `D:\vault-breaker-preservation` (Branch `master`, commits `1dcfdbf`, `b9134dd`, `6ea5ab5`)  
**Evidence Archive Directory:** `D:\vault-breaker-preservation\logs_preservation\live_test_20261119\`  

---

## 1. Executive Summary & Core Results

The purpose of this live integration test was to evaluate whether the authentic, isolated Marathon preservation client advances beyond BAP Service 304/305 using our newly implemented experimental synthetic SSC response generator (`--allow-synthetic-ssc`), without introducing forced-success client hooks.

### Summary Table: Protocol Progression

| Operation / Stage | Expected Behavior | Observed Result | Status |
|:---|:---|:---|:---:|
| **HTTP SignOn** | TLS Status 200, 748B payload, valid expiry | Handshake OK, entitlements granted (`3065800`, `3760193538`, `3760193537`) | **PASS** |
| **SDR Configuration** | `/ISteamApps/GetSDRConfig/v1` returns official JSON | Status 200, POP `sea` advertised | **PASS** |
| **Direct Settings** | Manifest and Global settings served | Status 200 for manifest & global JSON | **PASS** |
| **SDR Ping Router** | UDP 27015 ping reply | `RouterPingReply` dispatched (1300B & 55B) | **PASS** |
| **Content Manifest** | `content_manifest.pb` (31,424B) served | Status 200, package registration verified | **PASS** |
| **BAP Bootstrap (Svc 30/31)**| Plaintext Channel Start / Response | Status 200 (128 bytes) | **PASS** |
| **BAP Handshake (Svc 25/26)**| AES-128-GCM session negotiation | Status 200 (84 bytes), GCM session established | **PASS** |
| **BAP Service 304 (Request)**| Client transmits Ed25519 cert request | Received Task 2, parsed pubkey `c5e268c5b41d539a...` | **PASS** |
| **BAP Service 305 (Response)**| Synthetic Status 200 with protobuf cert | Encrypted Frame dispatched (Status 200, 167B body) | **PASS** |
| **TCP Socket Persistence** | Port 7505 remains open post-305 | Connection status verified `Established` | **PASS** |
| **Subsequent BAP Service** | Client transmits next BAP frame | **No subsequent frame sent by client** | **FAIL** |
| **Watchdog Timeout** | Engine transitions to activity or orbit | Waited 20.0s in State 26 $\rightarrow$ `error.no_bap_connection` | **FAIL (Centipede)** |

---

## 2. Test Execution Details & Environment

### 2.1 Backend Server Launch
- **Executable:** Python 3.11.9 (`C:\Users\marra\AppData\Local\Programs\Python\Python311\python.exe`)
- **Working Directory:** `D:\vault-breaker-preservation`
- **Command Line:**
  ```powershell
  $env:PYTHONPATH="scripts"
  python -u scripts/marathon_server.py `
    --bootstrap-token-file "D:\Marathon-preservation\analysis\content-token-recovery-20261117\content-token-candidate.bin" `
    --allow-synthetic-ssc `
    --ssc-capture-dir "D:\vault-breaker-preservation\analysis\ssc-captures"
  ```
- **Bound Ports:**
  - `TCP 8080` (HTTPS SignOn / TLS fallback)
  - `TCP 8081` (Plaintext HTTP fallback)
  - `TCP 80` (Plaintext Direct Settings)
  - `TCP 443` (HTTPS SignOn)
  - `TCP 7505` (BAP TCP Service Router)
  - `UDP 7505` (BAP UDP Service Router)
  - `UDP 27015` (SDR Ping Responder)

### 2.2 Client Launch
- **Executable:** `D:\Marathon-preservation\client-248199-retail-packages\Marathon.exe`
- **Working Directory:** `D:\Marathon-preservation\client-248199-retail-packages`
- **Proxy Configuration:** `marathon_client.ini` (`ServerIP=127.0.0.1`, `ServerPort=8080`, `SteamID=76561198000001001`)
- **Steam Proxy DLL:** Custom `steam_api64.dll` (Build `http-bootstrap-observation-v2`, 215,552 bytes)
- **Firewall Enforcement:** Windows Defender Outbound Block rule `MarathonPreservation248199RetailPackages` verified active on `Marathon.exe`.

---

## 3. Detailed Chronological Event Timeline

All timestamps recorded during the primary live run on 2026-11-19:

| UTC Timestamp | Local Time | Subsystem | Event Description |
|:---|:---|:---|:---|
| `03:21:57.120` | `22:21:57` | HTTPS POST | Client requests `/SignOn` (492 bytes, `peer_pid=26860`). Server returns Status 200 (748 bytes) granting entitlements. |
| `03:21:57.340` | `22:21:57` | HTTP GET | Client requests `/ISteamApps/GetSDRConfig/v1`. Server dispatches official config (7925 bytes). |
| `03:21:58.012` | `22:21:58` | HTTP GET | Client requests Direct Settings manifest and global JSON. Server returns Status 200. |
| `03:21:58.204` | `22:21:58` | UDP 27015 | SDR ping exchange: Client sends 1300B probe, server replies with `RouterPingReply`. |
| `03:21:59.105` | `22:21:59` | HTTP GET | Client requests `/GolRetail/content_manifest/content_manifest.pb`. Server serves 31,424 bytes. |
| `03:22:00.312` | `22:22:00` | BAP Router | Client connects from `127.0.0.1:49552` to TCP `7505`. |
| `03:22:00.345` | `22:22:00` | BAP Bootstrap | Client sends Svc 30 (Task 0, 130B). Server replies Svc 31 (Task 0, Status 200, 128B). |
| `03:22:00.380` | `22:22:00` | BAP Handshake | Client sends Svc 25 (Task 1, 38B). Server replies Svc 26 (Task 1, Status 200, 84B). AES-GCM channel negotiated. |
| `03:22:00.421` | `22:22:00` | BAP Svc 304 | Client sends Authenticated Type-1 Service 304, Task 2 (47 bytes). Server extracts ephemeral Ed25519 pubkey `c5e268c5b41d539ae53a8046976760197d2a15046e5cb6d80d770c2c8bf85262`. |
| `03:22:00.425` | `22:22:00` | BAP Svc 305 | Server generates synthetic SSC response fixture matching client's public key. Server encrypts and dispatches Service 305 (Task 2, Status 200, body=167 bytes). Nonce advanced. |
| `03:22:00.426` | `22:22:00` | TCP Socket | TCP socket on port 7505 remains open and `Established`. |
| `03:22:01.120` | `22:22:01` | Telemetry | Client POSTs `/anon/events` (4627B): Bootflow enters State 8 (`bootflow sos actions`), State 20 (`prepare for orbit`), and State 25 (`bap signin`). |
| `03:22:14.340` | `22:22:14` | Telemetry | Client reports UI navigation state change (`navigation_component_name_hash: 1862057413`). |
| `03:22:20.287` | `22:22:20` | Client Engine | Exactly 20,000 ms elapsed in State 26 (`accumulated_time_ms: 20002`). |
| `03:22:20.288` | `22:22:20` | Telemetry | Client fires `world_controller.retail_datamine.kto`: `current_state: ENUM(26)`, `remaining_tasks: 1`. |
| `03:22:20.288` | `22:22:20` | Telemetry | Client fires `world_controller.bootflow.request_state_change.error`: `state: "cleanup"`, `reason: "error.no_bap_connection"` (Centipede). |
| `03:22:32.100` | `22:22:32` | Retry Loop | Client re-executes SignOn, manifest download, and connects to BAP port 7505 on new port `55371`. |
| `03:22:33.489` | `22:22:33` | BAP Svc 304/305| Server again serves synthetic Status 200 (167B). Connection established. Client waits 20.0s and fires Centipede again. |

---

## 4. Relevant Log Excerpts

### 4.1 Server Handshake & Synthetic Response Dispatch (`marathon_server.log`)
```text
[2026-11-19 22:22:00] [BAP] Client connected from ('127.0.0.1', 49552) on port 7505
[2026-11-19 22:22:00] [BAP] Svc 30 (Task 0) <- 130 bytes
[2026-11-19 22:22:00] [BAP] Svc 31 (Task 0) -> Status 200 (128 bytes)
[2026-11-19 22:22:00] [BAP] Svc 25 (Task 1) <- 38 bytes
[2026-11-19 22:22:00] [BAP] Svc 26 (Task 1) -> Status 200 (84 bytes)
[2026-11-19 22:22:00] [BAP] Authenticated type-1 service=304 task=2 bytes_after_task=47
[2026-11-19 22:22:00] [BAP] SSC Request: task=2 key_type=1 pubkey=c5e268c5b41d539ae53a8046976760197d2a15046e5cb6d80d770c2c8bf85262 steam_id=None ident='None' apps=None
[2026-11-19 22:22:00] [BAP] SSC public capture decoded: D:\vault-breaker-preservation\analysis\ssc-captures\ssc304-811a8e3a40f6462ca838de39afb6a958.json
[2026-11-19 22:22:00] [BAP] Generated NON-PRODUCTION synthetic SSC response fixture for public key c5e268c5b41d539a...
[2026-11-19 22:22:00] [BAP] Encrypted svc 305 task=2 status=200 body=167 bytes
```

### 4.2 Decoded Service 304 Public Capture (`analysis/ssc-captures/ssc304-811a8e3a40f6462ca838de39afb6a958.json`)
```json
{
  "utc": "2026-11-20T03:22:00.421504+00:00",
  "task": 2,
  "request_bytes": 47,
  "request_sha256": "50c1da9dcba0b9b074cf2443177d7e9681dfb9408dcd5e0ffeec0e7f102fe671",
  "status": "decoded",
  "body_offset": 2,
  "key_type": "ED25519",
  "public_key_hex": "c5e268c5b41d539ae53a8046976760197d2a15046e5cb6d80d770c2c8bf85262",
  "public_key_sha256": "a405fc7f54545a9d7f34d67a4ad243d4bc24a11e435398ae02a8724f8b9f6aee",
  "identity": null
}
```

### 4.3 Client TCP Connection Persistence (Verified via `Get-NetTCPConnection`)
```text
LocalAddress  : 127.0.0.1
LocalPort     : 49552
RemoteAddress : 127.0.0.1
RemotePort    : 7505
State         : Established
```

### 4.4 Telemetry Kick to Orbit (`kto`) & Centipede Event (`telemetry_1795144950_55368.bin`)
```json
{
  "name": "world_controller.retail_datamine.kto",
  "version": "1",
  "format": "json",
  "seq_num": "26",
  "created_time": "1795144940287",
  "payload": {
    "session_id": "Thu_11192026_222140_0026860@x64_steam@76561198000001001@5E_EF_52_1B_FD_63_7A51",
    "platform_user_name": "76561198000001001",
    "time": 1795144940,
    "current_state": "ENUM(26)",
    "world_controller_state_status": 0,
    "world_controller_state_task_manager_requested_tasks": 8323071,
    "world_controller_state_task_manager_remaining_tasks": 1,
    "platform": "pc_x64",
    "sub_platform": "Steam",
    "state_change_reason_hash": 4195836351,
    "activity_duration_seconds": 39,
    "time_to_activity_seconds": 0,
    "sanitized_external_ip": "1.0.0.0",
    "locality": {"x": 0.0, "y": 0.0, "z": 0.0}
  }
}
```
```json
{
  "name": "world_controller.bootflow.request_state_change.error",
  "version": "1",
  "format": "json",
  "seq_num": "27",
  "created_time": "1795144940287",
  "payload": {
    "system_identifier": "x64_steam@76561198000001001@5E_EF_52_1B_FD_63_7A51",
    "platform": "x64",
    "state": "cleanup",
    "reason": "error.no_bap_connection",
    "sanitized_external_ip": "1.0.0.0"
  }
}
```

---

## 5. Forensic Analysis: Identification of the First Failing Operation

### 5.1 What Succeeded
1. **The Service 304/305 Protocol Contract is Correct:**
   - The wire framing, Protobuf field layout (Field 3 wrapping `CMsgSteamDatagramCertificateSigned`), Little-Endian nonce counter progression, and Task ID correlation operated without a single framing or parsing fault.
2. **The Socket Remained Open:**
   - Unlike previous tests where the server abruptly closed the socket upon returning Status 503, the server properly held the connection open in `Established` state.

### 5.2 Why Centipede (`error.no_bap_connection`) Still Fired
1. **The Certificate Trust Boundary at RVA `0x30154670`:**
   - As established in Phase 1 & 2 static analysis, the client decodes Service 305 with callback `0x2FA1FB90`, extracts the certificate message via protobuf reader `0x30A3F910`, and passes the inner signed certificate payload to the internal certificate installer at RVA `0x30154670` (`set_certificate`).
   - The installer verifies the cryptographic RSA signature against Valve's hardcoded root public key.
   - Because our experimental synthetic certificate fixture contains dummy/synthetic signature bytes (designated explicitly as non-authentic for safety and compliance), **`0x30154670` returns `0` (`false`)**.
2. **Watchdog Timeout in State 26 (`remaining_tasks: 1`):**
   - When `set_certificate` returns `false`, `0x16fadad45` records an internal failure and aborts certificate registration.
   - The internal `ISteamNetworkingSockets::GetAuthenticationStatus` (`0x32B2A220`, slot `0xA8` in vtable `0x330299c8`) remains in `k_ESteamNetworkingAvailability_CannotTry` or unready.
   - State 26 in `world_controller` has 1 pending prerequisite task (`remaining_tasks: 1`) waiting for Steam networking authentication readiness.
   - Exactly **20,000 ms** after dispatching Service 305 (`accumulated_time_ms: 20002`), the State 26 watchdog expires.
   - Because the task was never marked complete, `world_controller` triggers Kick To Orbit (`kto`), records `state_change_reason_hash: 4195836351`, and requests state transition to `cleanup` with reason `error.no_bap_connection` (Centipede).

---

## 6. Conclusion & Definitive Next Steps

This live test provides empirical proof of the exact networking trust boundary:

1. **A pure backend-side synthetic certificate response cannot satisfy Marathon's static cryptographic validation.**  
   Even with perfectly valid Protobuf serialization, Status 200, correct Ed25519 public key binding, and an open TCP socket, the engine's internal validator rejects any certificate not signed by Valve's private root signing key.
2. **Project Dawn's Architectural Strategy is Confirmed Mandatory:**  
   In Project Dawn (Destiny 2 Tiger engine), the identical barrier was overcome not by forging certificates, but by implementing two internal client hooks:
   - **Hook 1 (`set_certificate`, RVA `0x30154670`):** Force return value to `1` (`true`), accepting the local certificate payload.
   - **Hook 2 (`GetAuthenticationStatus`, RVA `0x32B2A220` / vtable `0x330299c8` slot `0xA8`):** Force return value to `100` (`k_ESteamNetworkingAvailability_Current`, `0x64`) and set output `m_eAvail = 100`.

With the backend BAP Service 305 exchange confirmed working and stable on the wire, implementing these two client proxy hooks is the definitive technical step required to satisfy State 26 and advance the client directly into Vault Breaker activity allocation.
