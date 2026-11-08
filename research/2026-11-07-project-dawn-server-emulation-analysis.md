# Project Dawn Architecture & Bungie Server Call Replication Analysis
**Target:** Bungie Tiger Engine (*Destiny 2* Build 86657 vs. *Marathon* Build 26136895)  
**Date:** 2026-11-07  
**Status:** VERIFIED ORIGINAL REVERSE-ENGINEERED ARTIFACTS

---

## 1. Executive Summary

Project Dawn (`isinternets/Dawn`) is an open-source private server and preservation framework for Bungie's Tiger Engine (specifically *Destiny 2* build `86657.20.08.23.1800.d2_rc`). While earlier initiatives like *Project Sunrise* focused primarily on client-side inspection and local offline map exploration, **Project Dawn engineered the authoritative server-side emulation layer** to replicate Bungie's live-service calls, state mutations, and activity hosting protocols.

By analyzing the source code of Project Dawn (`Dawn/src`) and its companion technical research repository (`isinternets/d2-research`, Chapters 3, 4, 5, and 6), we have established the exact wire protocols, state machine contracts, and network hooks required to replicate Bungie servers for *Marathon* (Steam build `26136895`).

---

## 2. The Four Pillars of Project Dawn Server Replication

```mermaid
flowchart TD
    subgraph Client["Marathon.exe (Game Client)"]
        CL_BOOT["Bootflow State Machine (46 States)"]
        CL_STEAM["SteamAPI (SteamUser023)"]
        CL_HTTP["HTTPS Client (libcurl / Schannel)"]
        CL_BAP["BAP Client Transport (TCP/TLS)"]
        CL_P2P["Activity Client (UDP / SDR)"]
    end

    subgraph DawnProxy["In-Process Hook (steam_api64.dll / Proxy)"]
        P_STEAM["SteamAPI Mock (AppID 26136895, Auth Ticket)"]
        P_DETOUR["Winsock / Egress Redirect Detour"]
        P_CERT["SSL/TLS Certificate Verification Bypass"]
    end

    subgraph DawnServer["Local Server Emulation (Loopback 127.0.0.1)"]
        S_HTTP["HTTP/Protobuf Service (SignOn Handler)"]
        S_BAP["BAP Router (Services 6/7, 8/9, 16/17, 25/26)"]
        S_ACT["Activity Host (AHWC) & Bubble Host (BHWC)"]
    end

    CL_STEAM -->|Intercepted by| P_STEAM
    CL_HTTP -->|Redirected by| P_DETOUR
    P_DETOUR -->|POST /SignOn| S_HTTP
    S_HTTP -->|Protobuf Response (cs_signon_token, Keys)| CL_HTTP
    CL_BAP -->|Connects to| S_BAP
    S_BAP -->|Service 7 & 17 Host Resolution| CL_BAP
    CL_P2P -->|UDP Replication Frames| S_ACT
    S_ACT -->|State 0x28 & Pedestal 1..4| CL_P2P
```

---

## 3. Protocol Specification & Wire Formats

### A. The Bungie SignOn Web API (`POST /SignOn`)
In both *Destiny 2* and *Marathon*, bootflow state `[25] bootflow account signin` issues an HTTP POST request:
- **Endpoint**: `https://signon.goliath.prod.deadorbit.net/SignOn?platform=steam&build=26136895`
- **Request Body**: `application/octet-stream` containing the binary Steam auth session ticket.
- **Response Format**: Binary Google Protobuf message (`Dawn/src/middleware/signon/response.cpp`):

| Tag | Field Name | Type | Description | Dawn Implementation Value |
|---|---|---|---|---|
| 1 | `kResponseErrorField` | Varint | Error code | `0` (`kNoError`) |
| 2 | `kResponseSuccessField` | Sub-message | Security & Session parameters | See sub-message below |
| 4 | `kCommonInfoField` | Sub-message | Account metadata | ID `1`, Silo `1`, Bootstrap Config Blob |
| 5 | `kSiloIdField` | Varint | Environment silo | `1` |
| 6 | `kContentBuildVersionField` | String | Client build identifier | `"d2legacy"` / `"248199.26.10.21.2300.gol_retail.rc"` |
| 8 | `kCapabilityFlagsField` | Varint | Feature flags | `0` |
| 10 | `kOwnedEntitlementsField` | Bytes | DLC & Season entitlement table | Pre-constructed bitset |
| 12 | `kServerTimeField` | Varint | Unix epoch timestamp | Current system time in seconds |
| 13 | `kEnvironmentField` | String | Environment tag | `"live"` or `"prod"` |
| 14 | `kExternalAddressField` | Varint (IPv4) | Client public IP | `127.0.0.1` (`0x7F000001`) |

#### SignOn Success Sub-Message (Field 2):
- **Field 1**: 16 reserved zero bytes.
- **Field 2 (`encryptionKey`)**: 32-byte AES key for BAP packet encryption.
- **Field 3 (`authenticationKey`)**: 32-byte HMAC/auth key.
- **Field 4 (`sessionToken`)**: `cs_signon_token` (opaque binary session cookie).
- **Field 5 (`expirySeconds`)**: Token lifetime in seconds (e.g. `86400`).
- **Field 6 (`relayAddress`)**: Steam Datagram Relay IPv4 address (`127.0.0.1`).
- **Field 7 (`relayPort`)**: Port for BAP / relay service.

---

### B. Bungie Access Protocol (BAP) Engine (`chapters/04-bap-and-secure-services.md`)

After SignOn, the client initiates a persistent connection to the BAP service port.

#### 1. Wire Framing:
- **Outer Header** (6 bytes):
  ```text
  [0x01] [Frame Type: 1B] [Payload Length: 4B Big-Endian] [Payload: N Bytes]
  ```
  - `Frame Type 0x00`: Plaintext client request.
  - `Frame Type 0x01`: Authenticated AES-GCM encrypted frame (12-byte little-endian nonce counter, 16-byte auth tag prefix).
  - `Frame Type 0x02`: Plaintext bootstrap request / response.

- **Inner Request Layout**:
  ```text
  [Service ID: 2B Big-Endian] [Task ID: 4B Big-Endian] [Request Body]
  ```

- **Inner Response Layout**:
  ```text
  [Service ID: 2B Big-Endian] [Task ID: 4B Big-Endian] [Status: 2B Big-Endian (200)] [Response Body]
  ```

- **Server Notification Layout**:
  ```text
  [Service ID: 2B Big-Endian] [Sequence: 4B Big-Endian] [Notification Body]
  ```
  *(Crucial Bug Fix from Dawn: Server notifications do NOT have a 2-byte status field. Emitting a status field corrupts payload offsets and crashes the client parser).*

#### 2. Essential BAP Service Route Map:

| Service ID | Direction / Type | Role in Dawn | Minimum Required Response for Marathon |
|---|---|---|---|
| **25 / 26** | Req / Resp | Secure Channel Negotiation | Handshake AES-GCM parameters & 84-byte hello envelope |
| **30 / 31** | Req / Resp | Channel Start | Echo client nonce to synchronize crypto counter |
| **18 / 19** | Req / Resp | Client Configuration | Echo client runtime tuning variables |
| **23 / 24** | Req / Resp | Account Translation | Return mapped account handle and Bungie Name |
| **21 / 22** | Req / Resp | Purchased Offers / Commerce | Return empty/default inventory & currency |
| **34 / 35** | Req / Resp | Skill Records / Progression | Return empty list (prevents pending task stall) |
| **42 / 43** | Req / Resp | Matchmaking Request | Return opaque 128-byte join descriptor |
| **6 / 7** | Req / Resp | Activity Session Allocation | Return valid nonzero `activity_session_id` |
| **16 / 17** | Req / Resp | Activity Host Resolution | Return IP:port pointing to the local Activity Host |
| **8 / 9** | Req / Notif | Activity State Messages | Broadcast objective assignments & world state |
| **250 / 251** | Req / Resp | Keepalive | Heartbeat ping-pong |

---

### C. Activity Host & Bubble Host Replication (`chapters/06-activity-replication.md`)

Tiger Engine divides world hosting into two roles:
1. **Activity Host (`AHWC`)**: Runs session coordination, fireteam roster, and authored mission state.
2. **Bubble Host (`BHWC`)**: Runs the physics, combat AI, and local map simulation.

#### Key Replication Mechanics Recovered in Dawn:
- **Entity Slot Bitmask**: 8,192 slots represented by a 1,024-byte mask.
- **Region Value Math**:
  $$\text{region} = 8 \times \text{bubble\_ordinal} + \text{state\_ordinal}$$
  $$\text{bubble\_ordinal} = \text{region} \gg 3$$
- **Two-Phase Publication**:
  - *Phase 1*: Roster registration (groups, slots, entity types).
  - *Phase 2*: Body consumption (component payloads, active script variables, objective states).
- **Activity State Publication (Service 9)**:
  Pushes state updates directly to client listener `8080B8F1` Slot 10, invoking event `0x28` to advance Vault Breaker phases.

---

## 4. How Dawn Bypasses Client Anti-Tamper & SSL Pinning

1. **In-Process Proxy Architecture**:
   - Dawn compiles as a custom `steam_api64.dll` placed in the game folder.
   - The game loads this proxy DLL before initializing graphics or networking.
   - From `dllmain.cpp`, Dawn installs MinHook detours on:
     - `WS2_32.dll!connect` / `WSAConnect`: Intercepts outbound connections to `*.deadorbit.net` or `*.bungie.net` and redirects them to `127.0.0.1`.
     - Schannel / Crypto API (`CertGetCertificateChain`): Prevents SSL certificate validation failures for the local loopback server.
2. **BattlEye Neutralization**:
   - In *Destiny 2*, launching `destiny2.exe` directly bypasses `destiny2launcher.exe` (the BattlEye launcher).
   - In *Marathon*, launching `Marathon.exe` directly bypasses `MarathonLauncher.exe`. The internal AES-128 CTR decryption loop unpacks the `.text` and `.rdata` sections natively on the host CPU without needing BattlEye driver presence.

---

## 5. Direct Action Items for Marathon Standalone Emulation

Following Project Dawn's proven design, our next concrete steps are:

1. **Author `steam_api64.dll` Proxy Wrapper**:
   - Implement `SteamAPI_InitFlat`, `SteamUser023::GetAuthSessionTicket` (returning synthetic ticket), `SteamUtils010::GetAppID` (`26136895`), and `SteamNetworkingSockets012`.
   - Embed MinHook to redirect `deadorbit.net` to `127.0.0.1:8080`.
2. **Implement Minimal Dawn Python Service Emulator (`marathon_server.py`)**:
   - **HTTP Endpoint**: `POST /SignOn?platform=steam&build=26136895` returning the Protobuf envelope with `cs_signon_token` and mock keys.
   - **BAP Endpoint**: Outer/inner frame decoder responding to Services 25/26, 30/31, 18/19, 6/7, and 16/17.
   - **Activity Injector**: Push Service 9 notification selecting `g_key_pedestals_1..4` to advance the client into the Cryo Archive mission.
