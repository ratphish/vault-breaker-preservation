# Post-SignOn trace and verified transport fix

The verified defect fixed in this pass is **plaintext HTTP being redirected to
a TLS listener**. The baseline sends `127.0.0.1:80` to `127.0.0.1:8080`; the
server uses TLS on 8080. A standalone executable calling the actual baseline
hook failed to receive an HTTP response. The fixed hook received HTTP 200 with
a complete response body from the same already-running server.

This is a demonstrated proxy transport defect. It has **not** been demonstrated
to cause the current State 8 wait, and State 9 has not been verified. The fresh
capture does not include a decoded native HTTP request/result object.

## Dawn's actual completion path

Reference: `isinternets/Dawn`, commit
`57808bbc4aca5db9f4e04644b4b76803feb9c96b`, identified by the local Dawn 0.1.5.2
BUILD-INFO. Its separate waypoint patch has not been fully compared here.

1. [Native config getters](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/client/hooks/config_getter/config_getter_answers.cpp)
   provide a dedicated content URL (`dawn://local/config` in local mode) and
   persistent GUID token storage. This is separate from SignOn's `/cfg_a/`,
   `/cfg_b/`, `/cfg_c/` strings. The
   [SignOn extended-fields header](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/middleware/signon/extended/signon_extended_fields.h)
   explicitly says no reader for those optional fields is proven in that client.
   Treating them as an established manifest-fetch contract was unsupported.
2. The [local GET hook](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/client/hooks/network/content_config/request/content_config_get_replacement.cpp)
   recognizes that dedicated local route and builds a raw protobuf manifest.
   It writes the native request status, HTTP status and transferred byte count,
   issues a memory barrier, then clears the native pending flag. External-server
   mode calls the original enqueue function instead. Local unmatched routes
   complete with zero bytes, not JSON `{}`.
3. The [manifest encoder](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/middleware/content/manifest/content_manifest_encoder.cpp)
   writes entitlement data, installed-package rows and the GUID. The URL/token
   getters and encoder must agree; a generic JSON response is not that manifest.
4. The [content tick hook](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/client/hooks/network/content_config/tick/content_config_tick_replacement.cpp)
   reasserts a disabled signature gate, then invokes the native tick. The native
   state machine still owns progression.

The Marathon proxy currently redirects socket traffic; it does not implement
this native getter/GET/tick group. That architectural difference is established
in source, but its absence is not proof that Marathon needs the same hooks.
Normal native HTTP code can own completion after a valid socket response.
The Destiny result offsets (+0/+8/+12/+16), signature gate and GUID format have
not been established for Marathon and were **not** copied or patched.

## Fresh Marathon trace

Input: `D:\Marathon-preservation\analysis\state8-pid12348`, user-captured PID
12348 at State 8. Manifest integrity checks pass. See the preceding
`2026-11-10-dawn-bootstrap-parity.md` for capture identity and hashes.

`scripts/trace_bootstrap_calls.py` now follows the actual overlapping call,
register-call and push/ret stubs in an offline Unicorn model. Every input range
is hash checked. It performs no process access or host API calls. Optional
missing code comes only from the explicitly identified prior synthetic .text
image, with its digest recorded. It stops on missing data or context-dependent
branches instead of fabricating a successful native operation.

The fresh captured code resolves the trampoline edges. Continuing through the
**synthetic** text produces these return redirects:

| Candidate call site | Redirected return RVA in the offline model |
| --- | --- |
| `0x2EF4C7E0` | `0x11BCE6A9` |
| `0x30291247` | `0x0FA2715E` |
| `0x30291255` | `0x123C8B96` |
| `0x3029126B` | `0x21012C2D` |

All four paths reach helper `0x31A11910`, which calls `0x308872C0`. The latter
reads a global at RVA `0x38F7CA68`, followed by `gs:[0x58]` and a thread-local
storage slot. The capture lacks that global and thread context; the model stops
before the read. This is **thread-local storage**, not network TLS encryption.
The modeled trace therefore does not identify a task counter, async pending
flag, manifest getter or stage-advance operation.

The apparent call at `0x3029124C` resolves outside the image when considered
in isolation. The earlier protected call has not been proved to return to that
instruction. Ordinary call fallthrough in the old linear disassembly cannot
be used to infer task-manager semantics.

Model output is retained privately at:
`D:\Marathon-preservation\analysis\state8-pid12348\bootstrap-call-model-checked.json`.
It clearly distinguishes captured bytes from synthetic model bytes.

## Code change

`client_proxy/transport_route.h` centralizes port/protocol selection.
`client_proxy/steam_api64.cpp` applies it to connect, WSAConnect, ConnectEx and
WinHTTP. Existing loopback endpoints retain their original address and port;
127/8 and IPv6 loopback aliases are recognized. Redirected port 80 stays on
plaintext port 80. External 443/8080 traffic uses the configured TLS fallback,
and BAP remains on 7777. Socket address buffers are checked for sufficient size
before copying, and caller-owned inputs are unchanged.

This does not add an IPv6 server listener or change the original hook coverage
of IPv6 WSAConnect/ConnectEx. It fixes the transport policy where these hooks
already act. Existing server requirements, including a port-80 HTTP listener,
remain. No new native engine hook, exception handler, breakpoint or guessed
completion write was introduced. Prior diagnostic-proxy work was left intact.

`client_proxy/build_candidate.bat` builds to `artifacts/bootstrap-fix` and runs
the real hook functions in a standalone native test executable. It does not
run DllMain, load the proxy DLL, patch an IAT, deploy files, or start the game.
The old `build_proxy.bat` deploys automatically; do not use it for this procedure.

## Verification performed

- Candidate DLL compiles with the installed x64 MSVC toolchain.
- The same hook harness fails against the preserved baseline source: plaintext
  loopback 80 is observed as 8080.
- Candidate hook harness: **368 assertions passed**, with all socket operations
  stubbed. This covers real hook entry points, loopback endpoints, HTTP/TLS/BAP
  separation, a custom TLS fallback port, and preservation of input addresses.
- End-to-end standalone native hook probe against the existing loopback server:
  baseline failed with zero HTTP bytes; candidate returned HTTP 200. The final
  candidate probe also verifies Content-Length against the complete body.
- Existing Python settings/server/audit regressions: **26 passed in 2.27s**.
- New offline tracer controls: **4 passed in 0.98s**. These verify computed
  push/ret flow, stopping before unknown data reads or conditional branches,
  and rejection of changed capture bytes. Native Unicorn runs in subprocesses
  to isolate its Windows exception handling from pytest's faulthandler plugin.
- Both installed game DLLs still hash to the original
  `14D835863464502839D9E624B9E2A26F85130508F3B0066BF859A54A8CF213C8`.

## Exact tests

These commands do not launch the game or deploy the candidate:

```powershell
Set-Location -LiteralPath 'D:\vault-breaker-preservation'
cmd.exe /d /c client_proxy\build_candidate.bat
```

Expected: the explicitly labeled baseline regression fails, then the candidate
passes 368 assertions; the build command exits 0. Output candidate:
`D:\vault-breaker-preservation\artifacts\bootstrap-fix\steam_api64.dll`.

With the existing local service listening on port 80:

```powershell
& '.\artifacts\bootstrap-fix\transport_baseline_test.exe' --http-probe
$baselineExit = $LASTEXITCODE
& '.\artifacts\bootstrap-fix\transport_test.exe' --http-probe
$candidateExit = $LASTEXITCODE
[pscustomobject]@{ BaselineExit = $baselineExit; CandidateExit = $candidateExit }
```

Expected: BaselineExit 1, CandidateExit 0; candidate reports HTTP 200 and a complete
body. Requests are tagged `preservation-native-routing-probe` in the server log.
This is a standalone probe; it does not inject the candidate into Marathon.

```powershell
$env:PYTHONPATH = 'D:\Marathon-preservation\tools\python;D:\vault-breaker-preservation\scripts'
python -m pytest -q tests/test_direct_settings.py tests/test_state8_evidence.py tests/test_marathon_server.py tests/test_bootstrap_call_trace.py
```

Expected: 30 pass when the available Unicorn/Capstone dependencies are on that
path. Without Unicorn, the four tracer controls are skipped explicitly.

To reproduce the bounded model with a new output file:

```powershell
python scripts/trace_bootstrap_calls.py --capture 'D:\Marathon-preservation\analysis\state8-pid12348' --synthetic-text 'D:\Marathon-preservation\analysis\second-worker-text.bin' --output 'D:\Marathon-preservation\analysis\state8-pid12348\bootstrap-call-model-reproduced.json'
```

Expected: four traces stop at the missing native global/thread context, and the
isolated out-of-image candidate is reported as such. That stop is intentional.
Do not interpret it as a recovered HTTP task or successful bootflow transition.

A new State 8/9 game test requires a separately staged candidate and a manual
game run. No claim of a State 8 fix is justified by these transport tests alone.
