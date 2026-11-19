# Contributing to Marathon Vault Breaker Preservation

Thank you for your interest in contributing to the Marathon Vault Breaker preservation research project. This repository is dedicated to technical reverse engineering, protocol analysis, and clean-room emulation aimed at preserving the archived Marathon retail build (`248199.26.10.21.2300.gol_retail.rc`).

---

## 1. Operating & Legal Boundaries (Strictly Enforced)

To protect the integrity of this preservation effort, all contributors must adhere to the following principles:

1. **No Copyrighted Game Assets:**
   - Never commit or upload original game binaries (`Marathon.exe`), retail package archives (`.pkg`, `.pak`), extracted art/audio assets, or private cryptographic keys.
   - Reference game files by their clean SHA-256 digests, file sizes, or relative offsets in external environments.
2. **Clean-Room Analysis:**
   - All server implementations (`scripts/marathon_server.py`, `scripts/marathon_bap.py`) and client shims (`client_proxy/`) must be clean-room implementations developed through black-box network observation (packet captures) or public reverse engineering analysis.
   - Do not submit decompiled source code or proprietary Bungie/Sony SDK materials.
3. **Reproducibility & Evidence First:**
   - Every protocol finding or engine behavior claim must be backed by verifiable evidence:
     - Exact memory addresses / Relative Virtual Addresses (RVAs) from build `248199`.
     - Packet offsets and hex dumps from authenticated packet captures.
     - Automated regression tests (`tests/`) verifying expected behavior.

---

## 2. Current Research Priorities

We are actively looking for contributors with experience in:

- **Protocol Reversing (BAP / UDP / TCP):**
  - **Service 304/305 (Signed Steam Certificate):** Reversing the exact serialization structure expected by callback `0x2FA1FB90` / consumer `0x2FADAD10`.
  - **Post-Handshake BAP Flow:** Mapping services invoked after the Service 30/31 channel handshake.
- **Engine Bootflow Analysis:**
  - Analyzing state transitions in the engine dispatcher to understand what triggers progression from State 8 (`bootflow sos actions`) to State 9 (`bootflow checking content manifest`).
- **Telemetry Parsing:**
  - Decoding engine event dictionaries and reason hashes emitted during sign-in attempts.

---

## 3. How to Submit Findings

1. **Document in `research/`:**
   - When you discover a new function, packet structure, or engine milestone, document it as a markdown record under `research/YYYY-MM-DD-<topic>.md`.
   - Provide concrete evidence, disassembled instruction snippets, and reproduction steps.
2. **Add Tests:**
   - If adding or modifying emulation behaviors in `marathon_server.py` or `marathon_bap.py`, include a corresponding test in `tests/`.
3. **Pull Requests:**
   - Keep pull requests focused on a single topic or milestone.
   - Use conventional commit messages (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`).
