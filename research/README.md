# Research Archive & Investigation Index

This directory contains forensic logs, reverse engineering analyses, static disassembly audits, and packet capture comparisons for Marathon build `248199.26.10.21.2300.gol_retail.rc`.

---

## Chronological Investigation Log

### November 18, 2026 — BAP Channel Breakthrough & SSC Discovery
- [Build 248199 BAP Service 305 (Signed Steam Certificate)](2026-11-18-bap-ssc-response.md): Reversing services 304/305 (`"b->c ssc req"` / `"b->c ssc rsp"`), tracing callback `0x2FA1FB90`, consumer `0x2FADAD10`, and the `failed to set signed steam certificate` diagnostic.
- [Marathon BAP Channel Startup Correction](2026-11-18-bap-channel-start.md): Identified TCP 7505 magic 1, type 2 framing and implemented verified Service 30/31 handshake based on live capture stream 77.
- [Preserved 248199 Client Reaches BAP Connectivity](2026-11-18-content-token-bap-breakthrough.md): Resolved Marmot package-registration failure via recovered 16-character content token (`0x32D24A40`), leading to loading screen progression and initial TCP 7505 connection.
- [Content Token BAP Evidence](2026-11-18-content-token-bap-evidence.json): Companion evidence file recording verified hashes, timing, and TCP traces.

### November 13–14, 2026 — Manifest Delivery & Bootflow Hooks
- [Real Local Manifest Status](2026-11-14-real-local-manifest-status.md): Verification of signed content manifest delivery on HTTP 200.
- [Bootflow Hook Audit](2026-11-14-bootflow-hook-audit.md): Dynamic hook and injection verification for observing engine state transitions.
- [Initialization Passthrough Fix](2026-11-13-initialization-passthrough-fix.md): Correction of client initialization routines and local passthrough proxying.
- [Retail HTTP Contract](2026-11-13-retail-http-contract.json): Formalized endpoint contracts for local mock server.

### November 11, 2026 — SignOn Expiry & Native Configuration Trace
- [Observed Native Receivers](2026-11-11-observed-native-receivers.md): Tracing native worker thread completion and socket consumers.
- [SignOn Expiry Correction](2026-11-11-signon-expiry-fix.md): Fixed timestamp and lifetime mismatch in Protobuf SignOn response.
- [Expiry Retest & Native Config Candidate](2026-11-11-expiry-retest-and-native-config-candidate.md): Auditing common config keys and candidate CommonInfo structures.

### November 10, 2026 — State 8 & Dawn Protocol Alignment
- [Native SignOn Completion Proved](2026-11-10-native-signon-completion-proved.md): Established complete 280-byte SignOn response acceptance at native layer.
- [Dawn DLL & State 8 Comparison](2026-11-10-dawn-dll-and-state8-comparison.md): Comparing Steam callback ABI and callback IDs against Project Dawn reference.
- [Post-SignOn Trace & Routing Fix](2026-11-10-post-signon-trace-and-routing-fix.md): Fixing HTTP-to-TLS redirection defects in proxy transport.
- [State 8 Verification & Tests](2026-11-10-state8-verification-and-tests.md): Correcting unsupported claims from initial triage and isolating the State 8 wait loop.
- [HTTP Bootstrap Observation](2026-11-10-http-bootstrap-observation.md): Correcting Winsock ordinal hooking and dynamic DNS resolution tracing.
