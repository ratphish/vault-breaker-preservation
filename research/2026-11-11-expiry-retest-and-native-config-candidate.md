# State 8 expiry retest and native configuration candidate

The manual retest delivered the expiry correction but still stalled at State 8.
At 08:37:00 EST on November 11, server PID 12816 answered client PID 23176
with 281 bytes, server time 1794404220 and expiry 1794490620. The same client's
launch monitor reported State 8 at 08:38:17.785. This disproves the claim that
the expiry correction alone releases this wait.

The correlated proxy log records HTTP 200 and asynchronous reads for that
request. The new run has no captured native EOF/state snapshot; earlier native
completion evidence must not be silently attributed to PID 23176. No content
or BAP request appears in this bounded retest's server log.

## New native correspondence

Normal activated Dawn publishes a client content token into CommonInfo field
3, rather than using the standalone writer's flag-clear omission. See the
[pinned source comparison](2026-11-11-dawn-signon-consumption-reference.md).

Fresh read-only code from PID 27072 recognizes the same key `0x007b620f` at
RVA `313e28b7`, selects configuration destination `RDI+26c0`, and calls
`2feb7bb0`. That reader obtains a length, reads bytes and appends a NUL.
The exact full CommonInfo-to-dispatcher execution chain remains unproved.
The separate magic comparison `0x00123456` is at fresh RVA `14810cb5`.

The fresh configuration-dispatch prologue loads the configuration holder at
RVA `3679c298`. Its pointer is encoded. In PID 11972 the holder supplies decoder
RVA `1d1423b8`; the captured trampoline resolves to `0f01e2ca`. Its recovered
instruction path constructs a constant mask from immediate values, without
reading a secret or executing code inside Marathon. XORing the captured holder
with that mask produces a readable configuration object.

Six neighboring fields exactly match the fresh initializer: offsets `26a4`,
`26a8`, `26b1`, `26b4`, `26b8`, `26bc` contain 1, 1, 0x0101, 5, 5, 60.
The first 16 bytes at `26c0` exactly match the fresh static default at RVA
`32d24a30`. They have the shape of a 15-character string followed by NUL.
This establishes an authentic native configuration value, not a fabricated
random token. Its Dawn-equivalent content-token meaning remains an inference
from the shared key and initialization pattern, not a recovered field name.

Private source snapshots and the secret-free provenance record are in
`D:\Marathon-preservation\analysis\content-11972-20261111-0852`.
`native-bootstrap-candidate-provenance.json` records hashes of every result,
the pointer decoder identity, default checks and exact constant equality.
The separate 16-byte candidate file stays outside the repository.

## Controlled candidate, not a demonstrated fix

`--bootstrap-token-file` opts into a 29-byte CommonInfo entry using the supplied
16 raw bytes. Default server behavior continues to omit it. Both magic and
key exist in fresh Marathon code; the encoding is independently byte-for-byte
equal to the installed Dawn 0.1.5.2 writer in an offline Unicorn run using a
synthetic token. No live game code or data is patched.

The 21 focused Python tests cover this option, strict token sizes, field
placement, default omission, expiry and existing server behavior. They do not
prove State 8 acceptance. The next runtime comparison must observe a real
SignOn request using the enabled entry and then the same client's bootflow.

## Relaunch scope and limits

The user explicitly authorized relaunches while away. The agent started server
PID 27260 and game PID 27072 through the shell. That hidden launch stayed in
State 3 without SignOn. A single normal-window retry, PID 11972, also stayed in
State 3 with task 0 active. These are earlier startup waits, not reproduced
State 8 failures. No keyboard/mouse input or UI automation occurred. The first
read-only helper ended on target exit; the second has a bounded lifetime and
byte budget. Further launches are not justified by these unchanged results.

At 09:04:35 EST the agent replaced only its own server process with PID 14552,
enabling the experimental entry using the private native candidate file.
All five listener ports (80, 443, 8080, 8081, 7777) belong to that process.
Its startup log explicitly identifies the experimental mode. PID 11972 still
reported State 3 at 09:04:51, before any SignOn request to this server. Both
read-only helpers have ended; the second was explicitly stopped. No new DLL
was built or deployed.

The full targeted suite passed **87 tests in 4.47 seconds**. An independent
review found no blocking encoding issue and corrected two overstated comments.
The experimental server's stdout is
`D:\Marathon-preservation\analysis\server-bootstrap-20261111-090435.stdout.log`.

Reproduce the focused tests:

```powershell
Set-Location D:\vault-breaker-preservation
$env:PYTHONPATH = "$PWD\scripts"
python -m pytest -q tests/test_signon_bootstrap.py tests/test_signon_expiry.py tests/test_marathon_server.py
```

To reproduce the candidate server after stopping the existing server, use:

```powershell
python .\scripts\marathon_server.py --direct-settings-dir D:\Marathon-live\config\direct_settings --bootstrap-token-file D:\Marathon-preservation\analysis\content-11972-20261111-0852\native-bootstrap-candidate.bin
```

Omit `--bootstrap-token-file` to restore the baseline reply. Do not interpret
an enabled startup log, passing wire tests or the existence of a captured
default as proof that the State 8 dependency is satisfied.

## Resume check

### Candidate runtime test, 12:35 EST

Client PID 2228 received the candidate response (312 bytes) from server PID
24476. A read-only live snapshot of its SignOn HTTP object found request state
2, HTTP 200, 312 received bytes and CommonInfo fields 1, 2 and 3. The 32-byte
native stored token matched the reply's session-token field. The launch monitor
still reported State 8 at 12:36:39. Thus this candidate did not immediately
clear State 8; acceptance of CommonInfo field 3 is not established by a token
match. Response SHA-256: `c565449aeec2a0dad254ccd71c312fa126e08a56c12f91e3b488a883426c8dcc`.

At 12:35:57 this client PID also requested `GET
/ISteamApps/GetSDRConfig/v1?appid=3065800` and received HTTP 200. This corrects
any broader claim that the client makes no SDR-related request; it does not
establish that SDR gates State 8. No BAP transaction has been established.

### SDR ownership, 12:44 EST

In a subsequent State 8 run, PID 27716 owned UDP port 65039 while the local
server recorded two SDR pings from that same loopback port at 12:44:11 and
12:44:13. This ties SDR probing to the Marathon process, though it does not
identify the calling module or establish reply acceptance or readiness. The
server emitted replies; repeated requests alone do not prove they were rejected.
The fresh PID 27716 module snapshot lists PartyWin.dll and MobileNetworking.dll,
with no steamclient64.dll. The prior blanket attribution of SDR activity to the
separate Steam process does not apply to these observed packets.

The reconstructed image's SDR readiness-format string has four protected-code
reference candidates (RVAs `097b4621`, `164a0c52`, `1bda351c`, `20652bc9`).
These are synthetic-model candidates, not evidence that the references executed
or that any particular readiness value is true.

Fresh PID 24584 capture `sdr-24584-20261111-151816/result-000001.json`
verified all five requested page hashes. The four references do load the live
format string `SDR RelayNetworkStatus: avail=%s config=%s anyrelay=%s ...`.
Each also loads the same DWORD at RVA `3928dd58` into EDX before loading the
format into R8; that DWORD's role and the sources of the status arguments are
unproved. These pages do not establish the status values or runtime execution.
The helper was stopped after the bounded read. At 15:17:50 the same PID received
a 313-byte SignOn response and HTTP 200 on GetSDRConfig. The cause of State 8
is still unresolved.

The candidate server's saved stdout contains no SignOn response. On the later
resume check neither Marathon nor a listener on ports 80, 443, 8080, 8081 or
7777 was present. The old launch-monitor file therefore describes a past run,
not the current process. A candidate runtime result remains outstanding.

OpenCode v2.2.7 lists `ollama/qwen3-coder:30b` and its effective `local-re`
configuration denies `edit`, `shell`, `subagent` and `external_directory`, but
also begins with a wildcard allow. Those declarations alone do not establish
that every available write or execution tool is blocked. No local worker was
run against the project until enforcement can be independently verified.
