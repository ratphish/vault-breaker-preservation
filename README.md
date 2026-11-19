# Vault Breaker Preservation

> Clean-room reverse engineering and research toward offline preservation of Bungie's *Marathon* Retail RC build (`248199.26.10.21.2300.gol_retail.rc`, Steam AppID `3065800`).

---

## Overview

The primary objective of this project is to research and document the network protocols, engine state machines, and authentication handshakes required to restore playability to the unreleased PvE **Vault Breaker** extraction mode using authentic, unpatched client binaries in an isolated local environment.

This repository hosts clean-room protocol documentation, analysis scripts, regression test suites, and mock server implementations (`scripts/marathon_server.py`, `scripts/marathon_bap.py`).

> [!IMPORTANT]
> **Legal & Ethical Boundaries:** No copyrighted game executables, encrypted packages (`.pkg`, `.pak`), proprietary assets, or private keys are hosted in this repository. All research is conducted via clean-room protocol analysis and static reverse engineering. See [CONTRIBUTING.md](CONTRIBUTING.md) for full details.

---

## Current Status & Breakthroughs (November 2026)

```
[State 3: Title Screen] ➔ [State 4: Pre-Signin] ➔ [State 5: Platform Signin]
       ➔ [State 6: Account Signin] ➔ [State 7: Server Offline Check]
       ➔ [State 8: Bootflow SOS Actions] ➔ [State 9: Content Manifest (HTTP 200)]
       ➔ [Loading Screen / BAP Handshake (TCP 7505)] ➔ [Service 304/305: SSC (Current Blocker)]
```

### Major Milestones Achieved:
1. **Marmot Package Registration / Content Token Recovery:**
   - Identified and resolved the Marmot initialization barrier.
   - Recovered the authentic 16-character content token from native image offset `0x32D24A40` (SHA-256: `fa9b1440694d928e219ca80cee5535b259a67c4bb40f4b05cd23b9e0dcc6c5da`), matching the package header fingerprints (`0x281141FD`).
2. **Content Manifest Delivery:**
   - Server successfully serves the 31,424-byte signed content manifest over HTTP 200, allowing the client to transition past bootflow state 9.
3. **BAP Channel Startup (TCP Port 7505):**
   - The client reaches the loading screen and initiates a TCP connection to `127.0.0.1:7505`.
   - Reverse-engineered framing format (`magic 1`, `type 2`) and implemented verified Service 30/31 channel handshake aligned with retail network capture stream 77.
4. **Service 304 / 305 (Signed Steam Certificate):**
   - Identified BAP service pair 304/305 (`"b->c ssc req"` / `"b->c ssc rsp"`).
   - Located the client callback at RVA `0x2FA1FB90` and certificate consumer at `0x2FADAD10`.

---

## The Current Blocker (Where We Need Help!)

The isolated client successfully negotiates the initial BAP handshake on TCP 7505, but subsequent communication stalls on **Service 305 (Signed Steam Certificate)**.

- **Current Symptom:** The client logs:  
  `networking:server:bap:protocol_source: failed to set signed steam certificate`  
  and eventually times out with telemetry error `error.no_bap_connection` (Centipede).
- **Core Investigation Need:**
  - Analyzing how the decoded buffer at `0x2FADAD10` expects the Signed Steam Certificate to be packed, signed, or enveloped inside Service 305.
  - Investigating whether a valid mock Steam App Ticket or ECDSA-signed certificate payload satisfies `0x30154670`.

If you have experience with Steamworks authentication tickets, Bungie Action Protocol (BAP), or reverse engineering x64 Windows games, check out our [Contributing Guide](CONTRIBUTING.md) and open an Issue or PR!

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
