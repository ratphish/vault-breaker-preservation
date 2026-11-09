# Senior Reverse Engineering Consultation: Bungie Tiger Engine (Marathon Build 26136895) Bootflow Halt

## 1. Context & Objective
We are reverse-engineering Bungie's *Marathon* (Steam build `26136895`, version `248199.26.10.21.2300.gol_retail.rc`, Steam AppID `3065800`) to enable offline standalone preservation and emulation of the PvE activity **Vault Breaker** (Cryo Archive).

We have established the local server emulation stack (Project Dawn / Sunrise architecture):
- Local HTTP SignOn service on `127.0.0.1:8080` (Protobuf envelope).
- Local BAP (Bungie Access Protocol) router on `0.0.0.0:7777`.
- Winsock IAT hooks (`WS2_32!gethostbyname`, `WS2_32!getaddrinfo`, `WS2_32!connect`) redirecting `deadorbit.net` / `bungie.net` traffic to `127.0.0.1:8080`.
- 627 hardlinked `.pkg` asset packages in `packages/`.
- Custom in-process Steam API emulator (`steam_api64.dll`).

## 2. Major Milestone Just Achieved
The authentic client executable `Marathon.exe` booted on Windows 11 with DirectX 12 at 4K resolution (3840x2160).
The authentic loading screen (DNA/vertebrae column glyph with neon green nodes) rendered successfully.

Our Steam API emulator successfully passed all initial checks:
1. `SteamAPI_RestartAppIfNecessary(3065800)` -> returned `0` (`false`).
2. `SteamInternal_SteamAPI_Init` -> returned `0` (`k_ESteamAPIInitResult_OK`).
3. `SteamInternal_ContextInit` -> invoked callback with `+0x10` offset.
4. Resolved interfaces:
   - `SteamUtils010`: `GetAppID` -> `3065800`, `GetIPCountry` -> `"US"`, `GetSteamUILanguage` -> `"english"`.
   - `SteamUser023`: `BLoggedOn` -> `1`, `GetSteamID` -> `76561198000001001`, `GetAuthSessionTicket` -> handle `1`.
   - `STEAMUSERSTATS_INTERFACE_VERSION012`: `RequestCurrentStats` -> handle `1`.
   - `STEAMAPPS_INTERFACE_VERSION008`: `BIsSubscribed` -> `1`, `GetCurrentGameLanguage` -> `"english"`, `GetAvailableGameLanguages` -> `"english"`, `GetAppBuildId` -> `26136895`.
   - `SteamInput006`: `Init` -> `1`.

From Tiger Engine's official crash telemetry (`crash_info.txt`):
```text
language_system: english
language_ui: english
language_audio: english
language_current: english
world_controller previous_state: bootflow:media_check
world_controller state: bootflow:bootload
world_controller state_reason: normal_flow
world_controller state_status: bootflow:bootload (requested tasks: 0x00000000000019ff) (active tasks: 0x0000000000000001) (pending tasks: 0x00000000000019ce)
```
The client successfully advanced out of `bootflow:media_check` into `bootflow:bootload`!

## 3. The Current Runtime Failure
During `bootflow:bootload`, the engine halts with:
```text
halt:
### RUNTIME ERROR: EXCEPTION_ACCESS_VIOLATION at 00007FF71468000A
halt information:
  (<unknown>)
crash: tried to read address FFFFFFFFFFFFFFFF
thread information:
  thread_name: unknown, thread_id: 00007b6c
```
Address `0xFFFFFFFFFFFFFFFF` is `-1` (64-bit integer, e.g. `INVALID_HANDLE_VALUE` or `(uint64_t)-1`).

In the crash folder metadata (`ticketdbg_response.txt`), the files collected by the crash reporter include:
- `sku_config.txt` (552 bytes binary in game root, present)
- `direct_settings\global.json`, `activity_local_client.json`, `commerce_catalog.json`, etc.
- `cvars.xml` (present in `%APPDATA%\Bungie\Marathon\prefs`)
- `active_packages.txt` (0 bytes)
- `activity_options.txt` (0 bytes)

## 4. Consultation Questions for Senior Consulting Engineers
1. **`bootflow:bootload` Subsystem Mechanics**:
   In Bungie's Tiger Engine (Destiny 2 / Marathon), what specific subsystems are initialized during `bootflow:bootload` before it transitions to `bootflow:account_signin` / `bootflow:network_check`?
2. **Root Cause of `tried to read address FFFFFFFFFFFFFFFF`**:
   What is the standard cause of an access violation reading `-1` during `bootflow:bootload`?
   - Is it an unresolved file handle from `CreateFile` / `FindFirstFile` (e.g. looking for a missing configuration file, depot manifest, or package table)?
   - Is it a Steam API method returning `-1` or `0` on an unhandled query? For example:
     - `ISteamApps::GetAppInstallDir(appID, buffer, size)`
     - `ISteamApps::GetInstalledDepots(appID, pvecDepots, maxDepots)`
     - `ISteamApps::GetLaunchCommandLine(buffer, size)`
     - `ISteamApps::GetFileDetails(fileName)`
     - `ISteamUtils::IsAPICallCompleted` / `GetAPICallResult`
     - `ISteamUser::GetAuthSessionTicket` / `GetEncryptedAppTicket`
   - Is it a missing direct setting file, package descriptor, or command line argument?
3. **Recommended Fix Strategy**:
   What exact return values or stub implementations should our Steam API proxy or local environment provide to satisfy `bootflow:bootload` and allow the engine to proceed to the network sign-on stage?
