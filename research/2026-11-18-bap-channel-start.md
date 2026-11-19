# Marathon BAP channel startup correction — 2026-11-18

The isolated 248199 client reached TCP 127.0.0.1:7505 on November 18 at 00:06:32 Eastern. The old backend received service 30 with 130 decoded body bytes but answered service 31 with only 12 bytes in frame type 0. Centipede followed; this was a confirmed protocol mismatch, not evidence that the socket was unreachable.

Retail capture: D:\Marathon-preservation\captures\live-signin\marathon-live-network.pcapng, TCP stream 77, frames 11157/11158. Both frames are 142 bytes. Outer header is magic 1, type 2, big-endian length 136. Request inner header: service 30, task 0, reserved 0; response: service 31, task 0, status 200. Each has DESTINY followed by byte 1 and 120 opaque bytes. Response tail differs from request; an echo is not supported by the capture.

Saved native checks (RVA):
- 0x30BE4A70 copies response and byte-swaps header fields.
- 0x305E7840 checks outer magic 1; decoded continuation at 0x305E79A2 checks type against supplied 2.
- 0x30BE4B24 decoded payload 0x0DF2E400 requires inner length 0x88.
- 0x30BE4C98 supplies expected service 31/task 0 to header validation.
- 0x30B5FAD0 checks service; 0x304A9D30 requires status 200.
- 0x30BE4CC2 decoded payload 0x1982BDCD compares first body qword with marker at 0x32D4B120.
- Matching marker branches to 0x30BE4DE5 and then reaches 0x30BE4F0B / call 0x30B9B1D0. This initial acceptance path does not compare the remaining 120 bytes with the request.

Changed only backend handshake behavior: preserve incoming frame type in request object; validate type-2 service-30 body; return marker plus 120 fresh random bytes in type 2; serialize response frame type. Connection exceptions are now logged. No client patch, state forcing, debugger, firewall modification, or production contact.

Validation: 15 targeted pytest tests passed. Actual saved frame 11157 replayed through dispatch offline; generated response length and first 22 bytes match frame 11158. Tail deliberately varies. Evidence in D:\Marathon-preservation\analysis\bap-channel-start-20261118\native-checks.json and retail-replay.json.

Limit: full BAP authentication is not established. Existing service-25 reply is still a placeholder; subsequent traffic may expose the next missing protocol operation. Do not interpret this correction as successful login. Live validation pending backend restart and one isolated-client run. Backend PID 6124 was listening on 8080/7505 at verification; isolated-client outbound block and all firewall profiles enabled.
