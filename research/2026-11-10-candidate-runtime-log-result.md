# Routing candidate: first observed game run

User launched Marathon manually after the candidate replaced both installed
proxy DLLs. This pass only read logs/files and ran an isolated serialization
comparison; it did not send input, attach to the client, or alter its memory.

- PID 4404 started at 16:41:44 EST on November 10, 2026.
- Both installed DLLs still have candidate SHA-256
  `e39e7413b1771477eef6a92a9ca63b6134abd03b0404bbe1c8ecb9e14aed36bc`.
- Proxy startup reports installation of the Marathon executable's connect,
  DNS, file and certificate IAT hooks. It does not authenticate the loaded
  module's hash directly; the disk hashes and launch-after-deployment establish
  the installation provenance used here.
- SignOn returned HTTP 200 at 16:42:08. State telemetry progresses through
  states 1–7; state 7 took 44 ms.
- Fresh lmdetail identifies the same PID/session in state **8** at 16:43:32.423,
  with state duration **83,956 ms**. No state 9 observation was found.
- The inspected server-log interval since 16:41:44 contains SignOn and telemetry
  POSTs, but **zero GET or HEAD requests**. The last settings GET before that
  launch was an explicitly tagged standalone native probe at 16:38:47.
- The latest proxy launch segment contains no TCP/WinHTTP connection-call
  records despite successful server-side SignOn traffic. Hook-install logs
  therefore do not establish complete observation of the game's HTTP path.
- The startup event `launch_monitor.previous_launch_failed` describes a previous
  launch. It is not evidence that the present running client crashed.

SignOn response length was 280 bytes. That same size was already logged before
deployment (16:29 and 16:34), so it is not a new proxy regression. An isolated
in-memory serializer comparison, with logging suppressed and no sockets, shows
the first allocated membership ID 1 yields 279 bytes and the next ID 1002 yields
280 bytes. Protobuf varint width accounts for that difference. Field 4.3 remains
omitted in both cases. Total length alone is not a protocol-compatibility check.

Result: the routing correction did **not** resolve the observed State 8 wait in
this run. There is no observed settings/manifest GET on which to demonstrate
its effect inside the game. The independently reproduced transport defect
remains fixed, but native bootstrap request ownership, hook coverage and the
protected State 8 caller path remain the next investigation targets. Do not
claim that the game accepted a Direct Settings schema from the successful
standalone probes.
