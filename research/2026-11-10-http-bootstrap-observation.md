# HTTP bootstrap observation and Winsock ABI correction

The proxy had a concrete observation gap and an independent incompatible API
replacement. Both are fixed in the separately built `artifacts/http-trace`
candidate. Neither has yet been established as the cause of Marathon's State 8
wait. This candidate has not been installed. The running game's import slots
and HTTP completion path remain to be observed.

## Verified defects

`Hook_GetProcAddress` existed but the KERNEL32 IAT branch never installed it.
The main executable imports GetProcAddress and has no static libcurl imports.
Consequently, installing socket imports did not establish coverage of its
dynamically obtained HTTP APIs. No TCP hook messages alongside server SignOn
traffic was a coverage failure, not evidence that SignOn used no HTTP.

The old socket ordinal branch mapped ordinal 17 to sendto. The actual system
export is recvfrom; its final argument is an address-length pointer, whereas
sendto accepts a length value. Ordinal 20 is sendto. The same branch mapped
ordinal 60 to WSAConnect, but 60 is WSAEnumNameSpaceProvidersA; WSAConnect is 46.
The main executable and supplied libcurl import both 17 and 20. Replacing a
receive operation with sendto can prevent that receive operation, but it does
not establish that the stalled State 8 task calls this slot.

New ordinal binding compares resolved native exports with the original typed
function pointers. The standalone regression uses a synthetic IAT and the real
installer: the preserved baseline fails, and the corrected source passes.
A separate loopback UDP test verifies delivery of a complete datagram through
the retained ordinal-17 receive pointer.

REA exports are retained outside the repository:

- `D:\Marathon-preservation\analysis\rea-http-bootstrap-20261110.json`:
  supplied curl imports (`ev_06681acce0e2ca6c2764503a0a116bc7e340442be357f012c84604317c5faf86`)
  and host Winsock exports (`ev_82c8ff62cb570b0894103fdbcba370d6e61368e83eb8a493534072f28d732f46`).
- `D:\Marathon-preservation\analysis\rea-curl-exports-20261110.json`:
  curl exports (`ev_f3c88481d6275ac6e751e10dd999d966e674762df1b3ee473eacca3644d3e3be`).
- Supplied curl SHA-256:
  `0b2b0cdc35f4960daa160f0cf5150a292a4c82bc1a3c9358c50f062378903312`.

## Dawn reference and the boundary of the evidence

The source comparison is pinned to Dawn commit
`57808bbc4aca5db9f4e04644b4b76803feb9c96b`, as documented in
[the completion-path comparison](2026-11-10-post-signon-trace-and-routing-fix.md).
Dawn has separate native content URL/token getters, local manifest generation,
request status/byte-count publication, pending-flag clearance, and a native
content tick. Its SignOn cfg strings alone do not establish that contract.
Its Destiny request offsets and signature gate are not verified Marathon ABI.

The appropriate Marathon comparison is therefore: which API receives the
request, does its transfer run, what result is delivered, and does native
bootstrap consume completion? A successful server response alone answers
none of the latter questions. The new observer distinguishes enqueue, pump,
transfer completion and returned HTTP status without inventing a completion
or changing an application callback.

## Candidate instrumentation

- Installs the GetProcAddress IAT observer and scopes export replacements to
  the owning DLL. Missing and unrecognized exports keep their native result.
- Observes curl_easy_perform, curl_multi_add_handle, curl_multi_perform,
  curl_multi_socket_action and curl_multi_info_read. The last calls the native
  reader exactly once and returns the same message and queue count. It never
  drains an extra completion. Completed transfers record result, HTTP status,
  route and caller module/RVA. Query strings, fragments and URL userinfo are
  omitted/redacted. The variadic curl_easy_setopt API is untouched.
- Pins observed curl functions to the supplied export RVAs and refuses mixed
  module owners. These checks are not a full runtime DLL hash authentication.
- Observes WinHttpSendRequest/ReceiveResponse returns without claiming those
  returns prove asynchronous completion; native status callbacks are unchanged.
- Preserves GetLastError and errno across observation; publishes originals
  atomically. Repeated module scans are serialized without waiting on a lock
  during loader initialization. Hook logs include IAT slot and prior target.
- Adds UTC/PID/TID and periodic coverage counters; limits repetitive Steam
  polling messages. Curl pump logging is sampled after the first four calls.
- Server source now records peer PID from a reverse loopback TCP tuple where
  available. Attribution can be unknown after a connection closes. The current
  server must be restarted manually before this source change takes effect.

Already cached function pointers, alternative HTTP implementations, module
unload/reload, and API use before hook installation remain coverage limits.
The observer does not prove complete HTTP coverage. No native bootstrap field,
completion bit, content format, signature gate or state advance was patched.

## Validation and exact repeat commands

From PowerShell in `D:\vault-breaker-preservation`:

```powershell
cmd.exe /d /c client_proxy\build_http_trace.bat
$env:PYTHONPATH = "$PWD\scripts;D:\Marathon-preservation\tools\python"
python -m pytest -q tests/test_http_peer_owner.py tests/test_http_snapshot_parser.py tests/test_direct_settings.py tests/test_state8_evidence.py tests/test_marathon_server.py tests/test_bootstrap_call_trace.py
& .\artifacts\http-trace\ordinal_fixed.exe --udp-probe
& .\artifacts\http-trace\transport_test.exe --http-probe
```

Results: 64 observer assertions, baseline ordinal defect reproduced, corrected
ordinal regression passed, 368 transport assertions, 48 Python tests passed.
The UDP probe received its complete loopback datagram. The HTTP probe received
HTTP 200 and a complete body from the existing server. The HTTP probe is a
standalone test, not evidence of an in-game request. Without the tools/python
path, the optional Unicorn test module skips; the 48-test run included it.
No production proxy DLL was loaded by the native test executables; the curl
export test maps curl with DONT_RESOLVE_DLL_REFERENCES and invokes no curl code.

Candidate SHA-256:
`e28a219f2a7d1d3a433a113fcebc468c4119cb48fd5c202ac619787be3ac2acc`.
Both installed proxy files remain the earlier routing candidate:
`e39e7413b1771477eef6a92a9ca63b6134abd03b0404bbe1c8ecb9e14aed36bc`.
Build provenance is recorded in `artifacts/http-trace/validation.json`.

## Pending read-only evidence

The current shell was denied VM_READ access to elevated Marathon. The user-run
helper below needs an Administrator PowerShell. It only queries and reads an
already-running process; it does not launch, suspend, inject, write memory,
attach a debugger or send input. PID 4404 was still running when checked.
The output filename must not exist; preserve any failure report and use a new
filename for a retry.

```powershell
python D:\vault-breaker-preservation\scripts\capture_http_state.py --pid 4404 --expected-exe D:\Marathon-live\Marathon.exe --output D:\Marathon-preservation\analysis\http-state-pid4404.json --protected-context
```

This captures module identity and actual IAT targets for the main executable,
curl, Party and WinHTTP. It also captures a build-hash-pinned thread-local
storage record reached by the protected call model. Those sequential data
records are not CPU contexts or a call stack. Import identity likewise does
not prove execution. The fresh snapshot has not arrived at the time of this
report. It must be inspected before attributing the State 8 wait to either
proxy defect or attempting to extend the protected dispatcher model.

## Received runtime snapshot

The user subsequently supplied the successful PID 4404 capture. Its status is
complete with no errors: 185 modules, 123 selected imports, and 60 thread-local
storage records. The executable hash matches the pinned build. Source JSON
SHA-256 is `3b11efb7b337c75f3e64d53a4b91e2e30ec3d142bea7a0e155769e3d208518e8`.
The compact audit is [http-state-pid4404-audit.json](http-state-pid4404-audit.json).

| Importer / symbol | Captured slot | Captured target |
| --- | --- | --- |
| Marathon recvfrom ordinal 17 | `0x7ff697654a50` | proxy + `0x3e00` |
| libcurl recvfrom ordinal 17 | `0x7ffdcda1c368` | proxy + `0x3e00` |
| Marathon sendto ordinal 20 | `0x7ff697654a68` | native Winsock + `0x108e0` |
| libcurl sendto ordinal 20 | `0x7ffdcda1c370` | native Winsock + `0x108e0` |
| Marathon GetProcAddress | `0x7ff697654650` | native KERNEL32 + `0x33140` |
| libcurl GetProcAddress | `0x7ffdcda1c148` | native KERNEL32 + `0x33140` |
| Party GetProcAddress | `0x7ffd9f8881d0` | native KERNEL32 + `0x33140` |

Both captured ordinal-17 target prefixes match the installed disk DLL's bytes
at RVA 0x3e00. Disassembly at that RVA forwards the sixth argument as a 32-bit
value, consistent with the source's sendto wrapper rather than recvfrom's
pointer argument. The wrong receive binding and missing resolver observer are
therefore demonstrated in this running process, beyond the isolated fixture.

There is an important limit to this finding: a focused search of curl's x64
RIP-relative indirect calls finds its recvfrom call at RVA 0x53914, inside the
unwind function 0x538c0–0x53a0a. That function contains the short-packet error
string and packet processing consistent with the upstream
[TFTP receiver](https://github.com/curl/curl/blob/curl-8_11_1/lib/tftp.c).
This is an inference from source and binary correspondence, not full symbol
recovery. Curl's ordinary receive function at 0x65b0 calls native recv ordinal
16 at 0x6602 and reports stream receive errors. Its ordinal-16 import remains
native in the snapshot. The bad recvfrom binding must be fixed, but it cannot
be presented as a demonstrated ordinary HTTP receive failure. Marathon's own
uses of ordinal 17 and a State 8 dependency remain unresolved.

The protected thread-local storage index is 0. The data records have several
distinct values and in-image pointers, but identify no thread as the State 8
owner. Further inspection of the prior synthetic code shows the modeled
trampoline performs a self-modifying `lock xadd` before a conditional branch.
Neither a fresh counter value nor its execution is supplied by this snapshot.
Substituting an arbitrary thread's record would not establish the actual call
path. The model therefore remains bounded; these records are not task counts
or evidence for a pending bootstrap request.

A later lmdetail read still reports the same PID/session at State 8, updated
17:44:27.304 local, duration 3,738,838 ms. No current TCP rows for PID 4404 were
returned by the endpoint query; that is only an instantaneous observation.
The next informative experiment is a user-controlled run of the corrected
observer candidate, after closing the game for DLL replacement. That run must
establish the HTTP caller and native completion before a bootstrap fix can be
justified. The user has been asked to close the game; no replacement occurs
while it is running.

No UI control, game launch, live game memory write or deployment occurred in
this investigation. State 9 and a root cause for State 8 remain unverified.

## Subsequent authorized deployment

After the user confirmed Marathon was closed, a fresh process check found no
Marathon process. All source hashes in the build validation manifest and the
candidate DLL hash were verified before installation. Both installed proxy
DLLs were backed up and then replaced with the tested HTTP-trace candidate;
both installed SHA-256 hashes match
`e28a219f2a7d1d3a433a113fcebc468c4119cb48fd5c202ac619787be3ac2acc`.
The prior proxy log was copied into the backup directory without truncating
the active log.

Backup and deployment record:
`D:\Marathon-preservation\backups\proxy-http-trace-20261110-174710-f9926ab3\deployment.json`.
This record supersedes the earlier not-deployed status as installation
evidence; the build validation remains the record of the tested artifact.

The existing server PID 18460 was listening on TCP 80, 443, 8080, 8081 and 7777.
It was not restarted, so the additional server peer-PID logging is not active
in that already-running interpreter. The new proxy observer will become
active on the user's next manual launch. No game was launched by the agent.
