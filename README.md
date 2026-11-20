# Vault Breaker Preservation

> Clean-room reverse engineering and research toward offline preservation of Bungie's *Marathon* Retail RC build (`248199.26.10.21.2300.gol_retail.rc`, Steam AppID `3065800`).

---

## Overview

The primary objective of this project is to research and document the network protocols, engine state machines, and authentication handshakes required to restore playability to the unreleased PvE **Vault Breaker** extraction mode using authentic, unpatched client binaries in an isolated local environment.

This repository hosts clean-room protocol documentation, analysis scripts, regression test suites, and mock server implementations (`scripts/marathon_server.py`, `scripts/marathon_bap.py`).

> [!IMPORTANT]
> **Legal & Ethical Boundaries:** No copyrighted game executables, encrypted packages (`.pkg`, `.pak`), proprietary assets, or private keys are hosted in this repository. All research is conducted via clean-room protocol analysis and static reverse engineering. See [CONTRIBUTING.md](CONTRIBUTING.md) for full details.

---

## Current Status & Preservation Milestones (November 2026)

```
[State 3: Title Screen] ➔ [State 4: Pre-Signin] ➔ [State 5: Platform Signin]
       ➔ [State 6: Account Signin] ➔ [State 7: Server Offline Check]
       ➔ [State 8: Bootflow SOS Actions] ➔ [State 9: Content Manifest (HTTP 200)]
       ➔ [Loading Screen / BAP Handshake (TCP 7505)] ➔ [Service 304/305: SSC Handshake]
       ➔ [State 26: Networking Readiness] ➔ [Remaining Startup / Signin]
       ➔ [TARGET MILESTONE: Marathon Main Menu]
       ➔ [Activity Selection & Vault Breaker Allocation] ➔ [Cryo Archive In-Game]
```

### Preservation Milestone Roadmap

1. **Milestone 1 — Marmot & Content Manifest Registration [ACHIEVED]:**
   - Recovered authentic 16-character content token (`0x32D24A40`) and served 31,424-byte signed content manifest over HTTP 200.
2. **Milestone 2 — BAP Channel Startup [ACHIEVED]:**
   - Established TCP connection to `127.0.0.1:7505` and completed Service 30/31 and 25/26 handshakes.
3. **Milestone 3 — BAP Certificate Handshake & Networking Readiness [ACTIVE]:**
   - Implemented BAP Service 304/305 synthetic response contract.
   - Identified and reversed client-side certificate call chain (`0x2FA2017F` -> `0x30A3F910` -> `0x2FADAD10` -> `0x30154670`).
   - Confirmed client-side CA signature enforcement and State 26 polling on `ISteamNetworkingSockets::GetAuthenticationStatus` (`0x32B2A220`).
4. **Milestone 4 — Advance Beyond State 26 Without Centipede:**
   - Unblock State 26 (`remaining_tasks: 1`) via minimal proxy detours on `0x30154670` and `0x32B2A220`.
   - Observe the authentic protocol sequence and handle subsequent startup/signin operations.
5. **Milestone 5 — Reach the Marathon Main Menu [PRIMARY TARGET]:**
   - Complete bootflow sign-in, load UI assets, and reach an interactive, stable Main Menu.
   - **Preserve this state as a new verified working baseline before proceeding.**
6. **Milestone 6 — Activity Selection & Session Allocation Investigation:**
   - Investigate activity selection UI and protocol mechanics required to request Vault Breaker matchmaking / activity allocation.
7. **Milestone 7 — Load into Cryo Archive Vault Breaker Activity:**
   - Host and load the authentic Cryo Archive activity session.

> [!IMPORTANT]
> **Preservation Scope Notice:** The immediate milestone is **reaching the Marathon Main Menu**, not jumping directly into Vault Breaker. The client protocol sequence following State 26 will be observed and recorded rather than assuming speculative activity allocation requests. Once the Main Menu is accessible and stable, that working baseline will be archived before beginning activity launch research.

---

## Current Technical Blocker & Resolution Path

The isolated client successfully negotiates the BAP handshake and receives Service 305 on TCP 7505, but stalls on **State 26** waiting for Steam Datagram network authentication readiness:

- **Root Cause Confirmed (`SSC_CLIENT_RUNTIME_VALIDATION.md`):**
  - The client dispatcher at RVA `0x2FADAD10` strictly checks the boolean return of `0x30154670` (`test al, al; je error`).
  - Production binary validates the certificate against Valve CA public keys; synthetic certificates return `al = 0`.
  - `ISteamNetworkingSockets::GetAuthenticationStatus` (`0x32B2A220`, slot `0xA8`) remains stalled at `-101` (`k_ESteamNetworkingAvailability_CannotTry`).
  - State 26 times out after 20.0 seconds with `error.no_bap_connection` (Centipede).
- **Next Resolution Step:**
  - Implement minimal non-invasive diagnostic hooks in `client_proxy/` (`steam_api64.dll`) to satisfy `0x30154670` (`al = 1`) and `0x32B2A220` (`status = 100`).
  - Observe and document the authentic subsequent BAP services and sign-in requests leading to the Main Menu.

---

## Repository Structure

- [`research/`](research/) — Detailed reverse engineering notes, disassembly walkthroughs, RVA offsets, and packet capture audits. See [Research Index](research/README.md).
- [`scripts/`](scripts/) — Local backend implementation (`marathon_server.py`, `marathon_bap.py`), analysis tools, and disassemblers.
- [`client_proxy/`](client_proxy/) — C++ proxy (`steam_api64.dll`) and non-invasive diagnostic hooks.
- [`config/`](config/) — Emulated direct settings, SDR configurations, and manifest descriptors.
- [`tests/`](tests/) — Automated regression test suites verifying protocol contracts and parser behavior.

---

## Local Setup & Quickstart

### Prerequisites
- Windows 10/11 x64
- Python 3.11+
- (Optional) Visual Studio 2022 with MSVC v143 toolset (if building `client_proxy/`)

### Setup Instructions

1. **Clone the repository:**
   ```bash
   git clone https://github.com/ratphish/vault-breaker-preservation.git
   cd vault-breaker-preservation
   ```

2. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt  # or install pytest
   ```

3. **Configure Local Redirection:**
   Run [`setup_hosts.bat`](setup_hosts.bat) as Administrator to route Marathon's endpoint domains (`signon.goliath.prod.gravityshavings.net`, etc.) to `127.0.0.1`.

4. **Run the Emulation Server:**
   ```bash
   python scripts/marathon_server.py
   ```

5. **Run the Test Suite:**
   ```bash
   pytest tests/test_bap_channel_start.py
   ```

---

## License & Disclaimer

This project is an independent research endeavor for the purpose of digital software preservation and interoperability under fair use principles. *Marathon* is a registered trademark of Bungie / Sony Interactive Entertainment. This repository is not affiliated with, endorsed by, or sponsored by Bungie or Sony.
