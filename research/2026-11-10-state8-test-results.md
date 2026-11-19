# State 8 test results, November 10, 2026

Executed after the user authorized running the prepared tests.

- Focused pytest command from the procedure: **26 passed in 2.27 seconds**.
- An existing Python daemon, PID 18460, was already listening on ports
  80, 443, 8080 and 8081. No daemon restart was needed.
- HTTP transport probes were sent to all four listeners using User-Agent
  `preservation-agent-transport-probe`. Ports 443/8080 used HTTPS; the other
  two used HTTP. The local HTTPS probes skipped certificate verification;
  these results do not test certificate trust.
- On every listener, GET `global.json` returned 200, Content-Length 4,
  and response/header SHA-256
  `e3566b3a06430868d71e9287dfd6c6c520a3da027aabea01951d407ee131dc2f`,
  matching the local live-directory file.
- On every listener, HEAD returned 200 with the same length and digest.
- On every listener, GET `__missing_state8_probe__.json` returned 404.
- No `Marathon.exe` process was running when checked. No client capture or
  State 8/9 transition test was performed. No game launch or UI control was used.

These results validate server transport and the focused regressions. They do
not establish Tiger's settings schema, actual State 8 dispatch, or progression.
