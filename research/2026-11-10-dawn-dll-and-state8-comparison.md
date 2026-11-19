# Dawn DLL comparison and the observed Marathon HTTP path

The user's pasted comparison was read from
`C:\Users\marra\.codex\attachments\79bb6ea6-51c5-4903-9ffb-b143c363dd0b\pasted-text-1.txt`.
The earlier turn made concrete progress: it verified runtime import defects
and installed the tested v1 correction after the user closed the game.
This turn compares the actual DLLs, their relevant source contracts, and the
user's new manually launched PID 2044. The State 8 cause remains unproven.

## Artifact identity

[Static PE and string inventory](dawn-proxy-static-comparison.json) records
all exports/imports and selected diagnostic string offsets for these files:

| Artifact | Bytes | Exports | SHA-256 |
| --- | ---: | ---: | --- |
| Dawn 0.1.5.2 payload | 27,146,752 | 17 | `88c75ac8f411215a87a6e62758f9dcc34fb4bab903ebdec074c2e08164acc7c8` |
| Installed Marathon observer v1 | 212,992 | 24 | `e28a219f2a7d1d3a433a113fcebc468c4119cb48fd5c202ac619787be3ac2acc` |

The inventory's third row records the final, undeployed v2 artifact, also
identified by the matching source hashes in its validation manifest.

Dawn's three additional lifecycle exports are DawnInitialize,
DawnActivateClient and DawnShutdown. Fourteen Steam exports are shared with
ours; our extra exports provide newer flat-interface accessors and other Steam
entry points. Counts and file size do not measure functional compatibility.
Dawn has nine imported DLLs, including bcrypt and Winsock, and no static
WinHTTP/libcurl import. Our installed v1 imports four DLLs, including WinHTTP,
crypt32 and Winsock. Dawn's local routing hooks the engine executor rather
than depending on the OS calls our proxy observes.

REA PE-import evidence for Dawn, retained at
`D:\Marathon-preservation\analysis\rea-dawn-imports-20261110.json`:
`ev_e5bd5d763dd05d727e746852f37362c7b238119dd9a4e5418b314ed232803f47`.
The generic REA binary-layout provider rejected this Windows host (Linux x64
only); offline pefile/Capstone supplied the remaining portable inspection.
No DLL entry point was executed for this inventory.

Dawn BUILD-INFO pins source base
`57808bbc4aca5db9f4e04644b4b76803feb9c96b` plus a named waypoint hotfix.
That patch was not found locally; public source is the declared base, not a
proven byte-for-byte reconstruction of the patched DLL. Diagnostic literals
corroborate included subsystems, not their execution. Selected pinned source
files were retained privately under
`D:\Marathon-preservation\analysis\dawn-reference-source`.

The installed Marathon marker and hash identify `client_proxy/steam_api64.cpp`
as the source of this tested v1 build. The separate
`client_proxy/steam_api64_diag.cpp` is a different diagnostic implementation;
the pasted suggestion to use it must not silently substitute it for the DLL
actually running. Existing diagnostic-source work was preserved.

## A concrete shared Steam ABI defect

Dawn's [callback dispatcher](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/steam/runtime/callbacks/callback_dispatch.cpp)
uses MSVC slot 0 for call results and slot 1 for regular callbacks. Our source
had these reversed and used the four-argument function type for both. A
standalone MSVC test with compiler-generated overloaded virtual methods
reproduced the consequence: call results entered the regular overload with
no call handle; regular callbacks entered the call-result overload.

The [Valve callback declaration](https://github.com/ValveSoftware/Proton/blob/proton_9.0/lsteamclient/steamworks_sdk_153a/steam_api_common.h)
and the compiled fixture establish the ABI independently of Destiny's game
offsets. The new source selects the correct slots and signatures. The preserved
old-source fixture fails; the correction passes, preserving the 64-bit call
handle and exactly-once dispatch.

The same review found incorrect callback IDs. The
[Valve Friends017 header](https://github.com/ValveSoftware/Proton/blob/proton_9.0/lsteamclient/steamworks_sdk_153a/isteamfriends.h)
assigns PersonaStateChange to 304, AvatarImageLoaded to 334 and
GameRichPresenceJoinRequested to 337. Our source mislabeled 337 as persona
and 304 as avatar. PID 2044 registered both 304 and 337, and v1 dispatched
those mislabeled payloads. The corrected source publishes persona under 304
and avatar under 334, and never fabricates a 337 join invitation. The fixture
checks those delivery identities and the absence of the unsolicited join.

This comparison establishes actionable compatibility defects. It does not
establish that either prevents State 8: the running v1 client still obtains
app tickets and sends SignOn repeatedly. The callback implementation also
remains a small synthetic dispatcher, unlike Dawn's locked, event-owned queue;
the current tests do not prove general concurrent callback correctness.

Interface versions further constrain reuse. Dawn's declared base targets
SteamUser020, SteamInput001, SteamUtils009 and UserStats011; Marathon requests
SteamUser023, SteamInput006, SteamUtils010 and UserStats012 in this proxy.
Friends017 and Apps008 are shared. Copying Dawn's entire interface table would
not be justified by the shared callback ABI.

## Dawn's HTTP responsibility versus our proxy

The [descriptor router](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/client/hooks/network/http/http_descriptor_route.cpp)
handles an engine-owned descriptor and caller response buffer. In local mode
it routes supported POSTs in process, then skips the external executor.
External mode rewrites the URL and delegates to the original executor.

The [worker completion publisher](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/client/hooks/network/http/http_worker_completion.cpp)
writes downloaded bytes, HTTP status, transfer counters/rate and an atomic
finished request state. The outer worker subsequently publishes its result.
The separate ContentConfig GET path has its own result prefix and pending
flag. A low-level HTTP success is therefore a different milestone from
completion of the native request and its dependent bootstrap task.

Our installed proxy redirects and observes OS calls. The Python server
serializes responses outside the game. Neither is an equivalent native
request publisher. That missing implementation is a responsibility to
investigate, not proof that normal Marathon HTTP requires a replacement.
Native Windows transport can publish the result correctly on its own.

## What the new Marathon run proves

PID 2044 started manually at 17:50:33 local. Its v1 startup marker and hook
installation messages are present. The observed request path is **WinHTTP**:

1. SignOn opens at 17:54:04.852 local and sends 492 bytes through
   WinHttpSendRequest, return address Marathon RVA `0x311dd699`.
2. Send returns true, error 0; ReceiveResponse returns true at 17:54:04.861.
   The same server interval records the 492-byte POST, HTTP 200, and a
   280-byte response. This is matching process/request timing, not merely a
   standalone probe.
3. lmdetail at 17:58:48.595 still reports State 8, duration 283,895 ms, for
   this session. Back-calculating places entry at approximately 17:54:04.700,
   **before** the observed SignOn request. The label “post-SignOn State 8”
   should therefore not imply that the request had completed before entry.
4. Telemetry records an unmapped timed-operation ENUM(8) at 17:54:04.884
   with duration 183 ms. Its proximity is useful correlation, but its exact
   operation meaning and relation to the State 8 task are not recovered.
5. Ticket acquisition and SignOn repeat about every five minutes. The trace
   does not establish whether this is normal renewal or retry after failure.
6. The inspected coverage samples show zero curl easy/multi operations.
   The absence is bounded by observer coverage, not proof that no cached or
   alternative curl entry point can execute. No config GET was observed in
   the corresponding server interval.

The user supplied a fresh read-only capture:
`D:\Marathon-preservation\analysis\http-state-pid2044-code.json`, complete,
186 modules, 123 selected imports; source SHA-256
`f33422c6275ad5c78d4abc754b4459d6ec6f908653a05366b945b32db33dcc1a`.
All captured code/table hashes were checked. See
[the compact audit](http-state-pid2044-audit.json).

The fresh call at `0x311dd693` uses table slot `0x3530a850`, which contains
the installed proxy's observed SendRequest entry. The immediate native
instructions load request handle from object +0x10, body from +0x420, length
from +0x428, and pass the object as the WinHTTP context argument. On successful
send the wrapper also stores a time value at +0x10478. Those instruction-level
roles are established for this wrapper, not a complete request layout.
No guessed field was written.

The live function table identifies native ReadData, QueryHeaders and
SetStatusCallback pointers; ReceiveResponse/SendRequest point at our observers.
QueryDataAvailable points at an in-image thunk. These locations give concrete
next targets. The initial fresh window does not include all their callers or
the callback registration implementation. A follow-up bounded capture of
those exact regions was requested while the game remains running. The prior
synthetic text differs from fresh native code, so it cannot fill those gaps
as though it were current runtime evidence.

## Additional logging correction and candidate

Periodic IAT scans were calling the symbol resolver used for installation,
inflating the “dynamic resolves” counter and emitting repeat resolution lines.
v2 suppresses resolver event/counter emission for those internal scans; actual
hook-install records remain. Those inflated counts never proved application
calls or a loader retry loop.

v2 also observes WinHTTP numeric response-status queries, application reads,
available-byte queries, and native callback registration. Each observer calls
the original once, preserves arguments/outputs/errors, and leaves callbacks
unchanged. It logs callback code identity without replacing the callback.
Asynchronous API returns still do not claim completion or EOF. Response bodies,
header values and credentials are not dumped by these additions.

The final candidate is `artifacts/http-trace-v2/steam_api64.dll`, separate from
the installed v1 and its artifacts. It includes the verified Steam slot/ID
corrections and marker `http-bootstrap-observation-v2`. It is not deployed.

Repeat native validation:

```powershell
Set-Location D:\vault-breaker-preservation
cmd.exe /d /c "client_proxy\build_http_trace.bat D:\vault-breaker-preservation\artifacts\http-trace-v2"
$env:PYTHONPATH = "$PWD\scripts;D:\Marathon-preservation\tools\python"
python -m pytest -q tests/test_http_code_capture.py tests/test_http_peer_owner.py tests/test_http_snapshot_parser.py tests/test_direct_settings.py tests/test_state8_evidence.py tests/test_marathon_server.py tests/test_bootstrap_call_trace.py
```

Native results: 80 observer assertions, callback ABI/identity fixture passed,
old callback fixture failed as expected, old ordinal fixture failed as
expected, corrected ordinal fixture passed, 368 transport assertions passed.
Python results: 51 passed before the final documentation/provenance update.
These establish the tested contracts, not playable Marathon or State 9.

## BAP and content-manifest follow-through

The [separate BAP contract comparison](2026-11-10-dawn-bap-contract-comparison.md)
records reproduced differences between Dawn's cryptographic, connection-owned
channel and this repository's placeholder dispatch. It also covers manifest
GET/tick publication. The server's outer frame shape alone is not that channel.
No BAP transaction from the current State 8 client was established, so these
later readiness gaps must not be promoted to its present root cause.

The pasted “279-byte accepted baseline” is also too strong. Current response
size is 280 because of membership-ID varint width, and even an HTTP 200 or
parsed protobuf does not prove all native response consumers accepted it.
Marathon's actual reader and task transition remain the decisive evidence.

## End-of-pass runtime availability

A subsequent process inventory found no Marathon process and no PID 2044;
the proxy log ends at 18:43:03.005 local. The follow-up completion capture
file is absent. Consequently the pending PID-2044 capture command is obsolete
and should not be run. The original successful capture remains available for
offline work; no process was restarted or replaced on the basis of its exit.

The final separate v2 DLL SHA-256 is
`4c708f8e7ea0461650ab1c6c2d5e3a36dea1b03a740918efb8adc8b5943a6b04`;
`artifacts/http-trace-v2/validation.json` records the matching source hashes
and test results. Both installed copies were rechecked and still match v1.
The additional fixes have not been tested inside Marathon. No State 8 root
cause or progression to State 9 is claimed; runtime completion tracing needs
an available user-operated session and current PID.

## Subsequent v2 installation and remaining verification

The next goal turn revalidated the missing process/capture, checked every v2
source hash, and installed the tested v2 into both game locations after fresh
closed-process checks. Both installed hashes match the final v2 hash above.
Backups and the transaction record are at
`D:\Marathon-preservation\backups\proxy-http-v2-20261110-204020-6f34ad4a\deployment.json`.
This record supersedes the earlier undeployed status; no game was launched.

The [manual runtime procedure](2026-11-10-v2-manual-runtime-test.md) uses a
current PID and unique capture filename. Remaining verification is the
native completion/task relationship, actual response consumption, and State 8
progression. The previous goal turn was **progress** (new captured code,
reproduced ABI/ID defects, fixes and comparison evidence). This turn also makes
progress through verified installation and a concrete runtime procedure.

| Requested comparison requirement | Current evidence | Status |
| --- | --- | --- |
| Compare the actual Dawn and Marathon DLLs | Hashed PE inventory, exports/imports, diagnostic markers, build-info/source limits | Verified within static scope |
| Trace shared Steam callback behavior | Dawn source, Valve declarations, compiler-generated old/new dispatch fixture | Verified defect and correction; game effect pending |
| Compare HTTP dispatch and async completion | Pinned Dawn router/worker code, PID 2044 WinHTTP calls/table and fresh code | Architecture verified; Marathon engine completion unresolved |
| Compare bootflow/content initialization | Getter/GET/tick/install contracts in linked reports, fresh state telemetry | Responsibilities compared; Marathon native task ownership unresolved |
| Compare BAP with the separate Marathon server | Connection/crypto/service audit and in-memory probes | Implementation gaps verified; Marathon compatibility and current dependency unresolved |
| Implement Marathon-specific equivalents from evidence | Callback slot/ID and observer corrections installed; native tests pass | Partial; no guessed engine offsets or Destiny service bodies installed |
| Resolve the actual State 8 blocker | Requires current native response/task evidence and progression | Not achieved |
