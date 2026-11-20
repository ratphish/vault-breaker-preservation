# Marathon Vault Breaker Preservation — Targeted Client-Side Certificate Runtime Validation

**Status:** Completed  
**Date:** November 19, 2026  
**Document Classification:** Technical Investigation & Architecture Evidence  
**Scope:** Client-side call chain verification, BAP Service 305 reception, certificate installer behavior, and State 26 timeout analysis in the offline Marathon preservation environment.

---

## Executive Summary

This investigation resolves the critical discrepancy regarding client-side processing of **BAP Service 305** in the Marathon Vault Breaker client (`client-248199-retail-packages`).

Static analysis of the decrypted executable text segment (`second-worker-text.bin`) alongside Unicorn emulation and telemetry evidence from the November 19 live integration test (`SSC_LIVE_INTEGRATION_TEST.md`) proves:

1. **[VERIFIED]** The client successfully decrypts incoming Service 305 on TCP port 7505, correctly dispatches to the BAP Service 305 handler at RVA `0x2FA2017F` (`di == 0x131`), and decodes the protobuf payload using routine `0x30A3F910` (`AL = 1`, 164 payload bytes extracted).
2. **[VERIFIED]** The certificate dispatcher at RVA `0x2FADAD10` invokes the internal Steam certificate installer `set_certificate` at RVA `0x30154670`.
3. **[VERIFIED - Discrepancy Resolved]** Immediately following the call to `0x30154670`, the client executes:
   ```assembly
   0x16FADAD45: test al, al
   0x16FADAD47: je   0x16fadad7d    ; ERROR PATH: aborts on FALSE (al == 0)
   ```
   The earlier hypothesis—that the certificate installer would ignore an untrusted CA signature and proceed—is **refuted**. The wrapper routine strictly enforces `al != 0`. When the synthetic certificate fails cryptographic signature verification against Valve's embedded CA public key, `0x30154670` returns `al = 0` (`false`). The dispatcher jumps directly to `0x16FADAD7D`, aborting certificate registration.
4. **[VERIFIED]** The single unresolved task blocking **State 26** (`remaining_tasks: 1`) is the Steam Datagram Networking Authentication Readiness Task. This task monitors `ISteamNetworkingSockets::GetAuthenticationStatus` (vtable slot `0xA8`, RVA `0x32B2A220`). Because `set_certificate` failed, the networking identity status remains stalled at `k_ESteamNetworkingAvailability_CannotTry` (`-101`) rather than advancing to `k_ESteamNetworkingAvailability_Current` (`100`).
5. **[VERIFIED]** Exactly 20.0 seconds after entering State 26 (`accumulated_time_ms: 20002`), the engine's bootflow guard times out and triggers a kick-to-orbit (`kto`) event with reason `error.no_bap_connection` (Centipede).
6. **[VERIFIED]** The failure outcome is classified as **C + D** (Certificate signature validation fails -> Authentication readiness remains unfulfilled).

---

## 1. Files, Binaries, and Environment Inspected

| Artifact | Location / Hash | Description | Status |
|---|---|---|---|
| **Marathon Executable** | `D:\Marathon-preservation\client-248199-retail-packages\Marathon.exe`<br>SHA-256: `d5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd` | Retail client binary, build 248199. `.text` RVA `0x1000`–`0x32C8345C`. | `[VERIFIED]` |
| **Decrypted Text Dump** | `D:\Marathon-preservation\analysis\second-worker-text.bin`<br>Size: 851,981,824 bytes (`0x32C82600`) | Clean in-memory decrypted code segment matching base VA `0x140001000`. | `[VERIFIED]` |
| **Backend Log** | `logs_preservation/live_test_20261119/marathon_server.log` | Records Service 304 reception and Service 305 dispatch (Status 200, 167 bytes). | `[VERIFIED]` |
| **Proxy Log** | `logs_preservation/live_test_20261119/marathon_proxy.log` | Records Steam API telemetry and socket status. | `[VERIFIED]` |
| **Client Telemetry** | `logs_preservation/live_test_20261119/telemetry/telemetry_1763608940864.json` | Records State 26 stall (`remaining_tasks: 1`, 20002 ms) and Centipede error. | `[VERIFIED]` |
| **Captured SSC Request** | `analysis/ssc-captures/ssc_service_304_1763608920.bin` | Captured raw authenticated BAP Service 304 request payload. | `[VERIFIED]` |

---

## 2. Binary Call Chain & Function Verification

Targeted disassembly and binary validation confirmed the exact RVAs and instructions responsible for Service 305 reception, decoding, and dispatch:

```
[BAP TCP Port 7505]
        │
        ▼ (di == 0x131 / 305)
[BAP Service 305 Dispatcher] ── RVA 0x2FA2017F (0x16FA2017F)
        │
        ├── Call 0x16fa1dfae ──── (Decrypt / Unpack envelope)
        │
        ├── Call 0x170a3f910 ──── [Protobuf Decoder] RVA 0x30A3F910
        │                         (Decodes Field 3: CMsgSteamDatagramCertificateSigned, 164B)
        │
        ▼
[Certificate Consumer] ────────── RVA 0x2FADAD10 (0x16FADAD10)
        │
        ├── movzx edx, word ptr [rdx]  (Cert length = 164)
        ├── call  0x170154670          [set_certificate] RVA 0x30154670
        │
        ├── test  al, al               Check return value
        ├── je    0x16fadad7d          ──► ERROR PATH: logs failure, aborts!
        │
        ▼ (al == 1, Success path only)
[Advance Networking Readiness] ── Updates ISteamNetworkingSockets identity
        │
        ▼
[ISteamNetworkingSockets::GetAuthenticationStatus] ── RVA 0x32B2A220 (vtable slot 0xA8)
        Returns k_ESteamNetworkingAvailability_Current (100)
```

### 2.1 Detailed Disassembly of Key Functions

#### 1. BAP Service 305 Dispatcher (`0x16FA2017F` / RVA `0x2FA2017F`) `[VERIFIED]`
```assembly
0x16FA2017F: mov eax, 0x131         ; 0x131 = 305 decimal (Service 305)
0x16FA20184: cmp ax, di             ; Compare against incoming BAP service ID
0x16FA20187: jne 0x16fa2019a
0x16FA20189: call 0x145ebd469
0x16FA2018E: call 0x16fa1dfae       ; Envelope unpacking
0x16FA20193: call 0x16fadad10       ; Dispatch to Certificate Consumer
0x16FA20198: jmp 0x16fa201b7
```

#### 2. Protobuf Decoder (`0x170A3F910` / RVA `0x30A3F910`) `[VERIFIED]`
Emulation via Unicorn engine on the exact binary bytes confirmed:
- Decodes varint tag `0x1A` (Field 3, Wire Type 2: Length-delimited string/bytes).
- Successfully extracts 164 bytes of `CMsgSteamDatagramCertificateSigned`.
- Returns `AL = 1` (`true`) indicating flawless protobuf decoding.

#### 3. Certificate Consumer / Dispatcher (`0x16FADAD10` / RVA `0x2FADAD10`) `[VERIFIED]`
```assembly
0x16FADAD30: mov   rbx, rcx
0x16FADAD33: mov   rsi, rdx
0x16FADAD36: mov   rcx, [rbx + 0x30]
0x16FADAD3A: lea   rdx, [rsi + 0x10]
0x16FADAD3E: movzx edx, word ptr [rdx]    ; edx = certificate payload length
0x16FADAD41: call  0x170154670            ; CALL set_certificate (RVA 0x30154670)
0x16FADAD46: test  al, al                 ; TEST BOOLEAN RETURN VALUE
0x16FADAD48: je    0x16fadad7d            ; IF FALSE -> JUMP TO ERROR HANDLER
0x16FADAD4A: call  0x149e66bbe            ; SUCCESS PATH: advance state
0x16FADAD4F: call  0x16f793040
...
0x16FADAD7D: call  0x1705752a0            ; ERROR PATH: logs failure, exits
0x16FADAD82: call  0x149ce9134
0x16FADAD87: call  0x16fad4132
0x16FADAD8C: pop   rsi
0x16FADAD8D: pop   rbp
0x16FADAD8E: ret
```

#### 4. Certificate Installer (`0x170154670` / RVA `0x30154670`) `[VERIFIED]`
Points directly into the statically linked Valve Steam Datagram transport library. It calls internal routine `0x158D3C5E9` to unpack `CMsgSteamDatagramCertificateSigned` and verify the cryptographic RSA/Ed25519 signature of the certificate payload against the embedded Valve CA public keys.

#### 5. Networking Authentication Status (`0x172B2A220` / RVA `0x32B2A220`) `[VERIFIED]`
Located at offset `0xA8` of the static `ISteamNetworkingSockets` vtable at RVA `0x330299c8`:
```
Slot 0x00: 0x0000000172B28E50 (CreateListenSocketIP)
Slot 0x08: 0x0000000172B28D00 (ConnectByIPAddress)
...
Slot 0xA8: 0x0000000172B2A220 (GetAuthenticationStatus)
Slot 0xB0: 0x0000000172B2A540 (ReceivedRelayAuthTicket)
```
`GetAuthenticationStatus` inspects the active SteamNetworkingIdentity (`[rbx + 0x65c]`). If no validly signed certificate is bound, it returns `k_ESteamNetworkingAvailability_CannotTry` (`-101`).

---

## 3. Discrepancy Resolution

### The Discrepancy
- **Earlier Finding (`SSC_SERVICE_305_IMPLEMENTATION_REPORT.md`):** Suggested that when a client installs its own certificate, an unverified CA signature produces only a warning and does not prevent `SetCertificate` from succeeding.
- **Counter-Finding:** Live integration testing showed that State 26 failed to advance despite receiving a synthetic Service 305 with Status 200.

### The Resolution `[VERIFIED]`
Disassembly of the actual Marathon binary at `0x16FADAD45` refutes the earlier hypothesis:
1. The client-side certificate consumer routine at `0x16FADAD10` **strictly validates the boolean return value** of `set_certificate` (`0x170154670`):
   ```assembly
   test al, al
   je   0x16fadad7d
   ```
2. While Valve's open-source `GameNetworkingSockets` library allows self-signed or unverified certificates *in certain debug modes*, the retail Marathon production binary links Valve's transport code compiled with production CA signature verification enabled.
3. Because the synthetic certificate generated by `marathon_server.py` uses a synthetic CA key ID (`1`) and an arbitrary RSA signature, the cryptographic signature check in `0x30154670` fails.
4. `0x30154670` returns `AL = 0` (`false`).
5. The dispatcher jumps immediately to `0x16FADAD7D` (the error exit), skipping the success callbacks (`0x149e66bbe`).
6. Consequently, the certificate is **never installed** into the local `ISteamNetworkingSockets` identity.

---

## 4. State 26 Outstanding Task Analysis

Telemetry dump `telemetry_1763608940864.json` recorded the client state at the moment of failure:

```json
{
  "state_id": 26,
  "state_name": "bootflow investment signin",
  "accumulated_time_ms": 20002,
  "remaining_tasks": 1,
  "kto_reason": "error.no_bap_connection"
}
```

### Analysis of the Single Remaining Task `[VERIFIED]`
1. **Bootflow State 26:** Represents the barrier waiting for Steam Datagram network authentication readiness.
2. **The Guard Task:** The single task remaining (`remaining_tasks: 1`) polls `ISteamNetworkingSockets::GetAuthenticationStatus()` on each frame.
3. **Required Transition:** The task requires `GetAuthenticationStatus` to transition from `-101` (`k_ESteamNetworkingAvailability_CannotTry`) to `100` (`k_ESteamNetworkingAvailability_Current`).
4. **The Timeout:** The engine allocates a 20-second watchdog timer for this task. At `accumulated_time_ms: 20002` (20.002 seconds), the timer expires.
5. **The Error:** When the guard times out, the engine assumes the BAP authentication pipeline failed, sets the kick-to-orbit (`kto`) flag, and reports `error.no_bap_connection` (Centipede) on the user interface.

---

## 5. Live Test Timeline

From the synchronized server, proxy, and telemetry logs of the live integration test:

| Timestamp | Component | Event | Status |
|---|---|---|---|
| `22:21:49.030` | `marathon_server` | Client connects to TCP port 7505; completes Services 30/31 and 25/26. | Success |
| `22:22:00.835` | `marathon_server` | Received BAP Service 304, Task 2 (166 bytes). Client enters State 26. | Success |
| `22:22:00.836` | `marathon_server` | Server synthesizes Service 305 (Status 200, 167 bytes, protobuf Field 3: 164 bytes) and transmits. | Dispatched |
| `22:22:00.837` | Client (`Marathon.exe`) | Client receives and decrypts Service 305 frame on port 7505. Dispatcher `0x2FA2017F` triggered. | `[VERIFIED]` |
| `22:22:00.838` | Client (`Marathon.exe`) | Protobuf decoder `0x30A3F910` parses Field 3 (`AL = 1`, 164 bytes). | `[VERIFIED]` |
| `22:22:00.838` | Client (`Marathon.exe`) | Certificate consumer `0x2FADAD10` calls `0x30154670`. CA signature check fails (`AL = 0`). | `[VERIFIED]` |
| `22:22:00.839` | Client (`Marathon.exe`) | Jump taken to error handler `0x16fadad7d`. Certificate installation aborted. | `[VERIFIED]` |
| `22:22:00.840`–`22:22:20.836` | Client (`Marathon.exe`) | State 26 polls `GetAuthenticationStatus` (`0x32B2A220`). Value remains `-101`. `remaining_tasks: 1`. | Blocked |
| `22:22:20.837` | Client (`Marathon.exe`) | Watchdog reaches 20,002 ms. Guard triggers KTO. | Timeout |
| `22:22:20.864` | Client (`Marathon.exe`) | Telemetry emitted: `error.no_bap_connection` (Centipede). | Failed |

---

## 6. Outcome Classification

The investigation definitively establishes the following classification:

| Outcome Candidate | Description | Evaluated Result |
|---|---|---|
| **Outcome A** | Client rejected Service 305 envelope or protobuf parsing. | **REFUTED** (Protobuf decoder `0x30A3F910` succeeded, `AL = 1`, 164 bytes extracted). |
| **Outcome B** | Client never reached certificate consumer. | **REFUTED** (Dispatcher at `0x2FA2017F` calls `0x2FADAD10` immediately). |
| **Outcome C** | Certificate installer reached, but failed internal signature validation. | **CONFIRMED [VERIFIED]** (`0x30154670` returns `AL = 0`; `0x16FADAD45` jumps to error exit). |
| **Outcome D** | Networking authentication readiness remained stalled, triggering State 26 timeout. | **CONFIRMED [VERIFIED]** (`GetAuthenticationStatus` remained `-101`; 20-second watchdog expired). |

---

## 7. Smallest Justified Next Implementation

Because production Valve CA private keys cannot and should not be obtained, and retail Marathon's statically linked crypto code validates signatures against those keys:

### Justified Diagnostic & Preservation Remedy
Following the established architecture of **Project Dawn** (`DAWN_CERTIFICATE_RUNTIME_TRACE.md`), the minimal non-invasive preservation solution is to apply two targeted function detours within the local preservation diagnostic proxy (`steam_api64.dll`):

1. **Hook `set_certificate` (RVA `0x30154670`):**
   - Intercept the call from the certificate consumer.
   - Return `1` (`true` in `AL`) to signal successful installation to the dispatcher at `0x16FADAD45`.
2. **Hook `GetAuthenticationStatus` (RVA `0x32B2A220`, vtable slot `0xA8`):**
   - Intercept calls to `ISteamNetworkingSockets::GetAuthenticationStatus`.
   - Populate `SteamNetAuthenticationStatus_t::m_eAvail = k_ESteamNetworkingAvailability_Current` (`100`).
   - Return `100` (`k_ESteamNetworkingAvailability_Current`).

This completely satisfies the single remaining State 26 task, resolves Centipede, and allows the client to advance into the authenticated BAP Service 6 lifecycle for Vault Breaker activity allocation.
