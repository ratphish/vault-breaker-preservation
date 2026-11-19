# Marathon offline sign-in: current agent handoff

## Current deployment: baseline restored November14, 14:56 Eastern

User authorized backing up the experimental DLL and restoring the verified
baseline before a read-only code-page capture. Both root and bin/x64 DLLs
now hash ba01f2fbf4175815883768e2efd7ff07e7c5c5d065b108b79c97eb7f928fefbf.
Both prior8b39... copies were separately backed up and hashed under
D:\Marathon-preservation\analysis\experimental-proxy-backup-20261114-145606.
restore-manifest.json records exact paths/hashes. Firewall and all profiles
remain enabled; no client was launched. Backend16044 listens8080. This
supersedes any "experimental DLL remains deployed" status in older notes.
The next user-run read-only capture requests pages0bb98000/e755000 using
capture_http_state.py; no forced state, observer DLL or debugger.


## November14 deployment audit: supersedes deployment/backend status below

The user reports a newly deployed bootflow hook failed with Termite. Read
research/2026-11-14-bootflow-hook-audit.md before any next run. Both live DLLs
are now8b39afe884fabe17bd2660e7840e04bbefddc6226f2d310f08a318d35774f486,
not the previously restored baseline. Current backend PID16044 DOES include
a manifest replay route; it serves the unchanged31424-byte retail capture.
The alleged local-GET implementation is actually a stage bypass; it never
loads or publishes a manifest. PID10836 logs installation and an early
provider write but no intercepted-tick or advance call. Termite telemetry is
confirmed; task0 counters at ENUM(20) do not prove state8 task starvation.
No new test, rollback, source fix or deployment was performed by this audit.


Updated after the November 13, 19:35 Eastern read-only capture (PID5424).
This supersedes the earlier interpretation of state3 and the "error codes."
Sign-in is still stalled. No new client run or backend/DLL change occurred
in this follow-up. Do not automatically continue with another forced test.

## Objective and scope

Preserve build26136895 /248199.26.10.21.2300.gol_retail.rc in
D:\Marathon-live against the replacement local backend. Retail build-number
differences are expected; use retail for behavior/contracts. A targeted client
shim is acceptable when its state/data contract is established. Unforced
progression is evidence, not an absolute preservation requirement.

Keep the existing outbound firewall block enabled. No production Bungie
contact, TLS interception, anti-cheat instrumentation, or subagents. Earlier
one-run observer/forced-state authorizations and the candidate deployment test
are consumed. WinDbg disrupted startup; do not repeat it or propose TTD as
though compatibility was established.

## Latest finding: captured list is entitlements, not error codes

Evidence: D:\Marathon-preservation\analysis\signon-errors-20261113-193531.
Original error-summary.json and reader/result-000001.json remain unchanged.
The captured list is:

* 002ec7c8 =3065800 (Marathon Steam AppID)
* e0200002 =3760193538
* e0200001 =3760193537

All three exactly match backend SignOn field10 entitlements. Do not treat
these as engine errors or "fix" them by changing IDs. RVA367a2354 is their
retained array on this path;367a2454 is count3. The mask at367a2350 is0.
Its exact semantic name remains unresolved; the blanket "error flags" label
is withdrawn. scripts/capture_signon_errors.ps1 now uses neutral mask and
entitlement names. It still uses the existing read-only reader only.

Captured event kind4, underlying operation state3, task state4/result20,
HTTP state2/status200, received313 bytes. No complete execution trace.

## Native success-submessage path recovered

Static/private protected-block reconstruction recovered:

* HTTP polling call30c286cf uses slot10; once ready,30c286de invokes slot11.
  Its AL selects slot14 at30c286f2 versus fallback30c2870a.
* At30c28703,30b5c670 receives the known SignOn response buffer and byte count.
  It invokes response-application routine2fa17760 at30b5c7c7.
* In the response-code0 path,2fa1850d invokes success-submessage routine
  2faca8b0. Subsequent processing includes313ebc90 at2fa1853b.
* 2faca8b0 starts with R15B=false and event selector R12D=7. After session
  setup it sets R15B=true (source2facaa0d) and R12D=4 (source2facaa18).
  At2facada6 it tests R15B. The unsuccessful branch clears stored token/relay
  fields. The selected event is published through2facadd5 ->2f5b15b0.
* Event callback31a36940 is called at3148801a, with RCX pointing to367a21d0
  and RDX to event record367a2000. Event kind is at367a2018. Case4 writes
  state3 at protected source31a36a84 /payload1aa7699f, copies entitlements
  from the parsed SignOn object, and retains timing/silo data.

Classification: strongly supported native session-reply application success,
consistent with observed event4, retained entitlements and older exact token
matches. This is NOT proof of complete engine initialization or BAP readiness.
Do not label state3 alone as rejected payload. A recovered case4 diagnostic is
"networking:signon: Silo ID: %llu". Case2 has a reauthentication/server-offline
message; neither string was observed executing in the current capture.

The engine task's result20 is still published at2fb024bc from EBX14h.
Recovered assignment: protected source2fb0288d ->payload2225ea29,
`mov ebx,14h; jmp2fb02494`. Exact enum name remains unknown. Do not infer
Termite or payload rejection solely from this integer.

Detailed models/assessments in the latest evidence directory:
response-parser-30b5c670.json, signon-response-application-2fa17760.json,
success-submessage-2faca8b0.json, signon-success-path-assessment.json, and
entitlement-list-correction.json. These are static models, not a native
instruction recording. The bounded graph was corrected to follow internal
payload jumps; do not assume earlier incomplete graphs covered all branches.

## Earlier controlled tests and current deployment

Independent Steam/provider object state1 fails its readiness predicate;
state2 passes in a validated private replay. One authorized live four-byte
state1->2 test exposed user-reported Termite/configuration-download failure.
Evidence: D:\Marathon-preservation\analysis\force-state2-20261112-220651.
It does not establish that the SignOn payload was rejected or that20 names
Termite. It shows readiness and subsequent configuration are separate gates.

LocalSOS hooked slot3/RVA309c0620, which is INITIALIZATION before HTTP, not a
worker returning20. It waited30seconds for the HTTP that follows its own
forwarding, and could skip native initialization on a previous complete HTTP.
Source client_proxy/local_sos_actions.h now forwards initialization once,
without waiting or fabricating success. Isolated candidate built with native
regression tests passing at artifacts/local-sos-passthrough-20261113.

One candidate deployment test PID29676 completed and rolled back; user saw
straight-to-Signing-in, but the client still stalled. Evidence:
D:\Marathon-preservation\analysis\initialization-passthrough-20261113-191459.
163 read-only samples, HTTP200/312 bytes, operation0->1->3, task4/result20.
User closed normally, exit0; original DLL restored and independently hashed.
The one-run PASSTHROUGH_TEST_STARTED token is consumed. The original proxy is
currently restored, so its30-second delay is expected on subsequent launches.

Baseline DLL SHA256:
ba01f2fbf4175815883768e2efd7ff07e7c5c5d065b108b79c97eb7f928fefbf
Candidate SHA256:
bbe619358ce87d1708345776988e42cb8c15551d5c18b8fc238d2a8768b484c8
Executable SHA256:
d5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd

## Backend and retail configuration replay

Backend last verified PID7112, listening80/443/8080/8081/7777. It retains the
previous bootstrap-token-file option and settings directory
D:\Marathon-live\config\direct_settings. Source scripts/marathon_server.py.
Do not trust older CODEX_HANDOFF.md or steam_api64_diag.cpp as current authority.

Original captures: D:\Marathon-preservation\captures\live-signin\
marathon-live-network.pcapng, marathon-live-procmon.PML, marathon-live-procmon2.PML.
SignOn is encrypted, but retail direct-settings/content GETs are plaintext.
Two exact JSON responses were extracted and are now served under their hashed
filenames through /GolRetail/direct_settings/: manifest3226 bytes, global2907
bytes. Both active responses were verified byte-for-byte over loopback.
Content manifest31424 bytes is retained as evidence, not served. Retail build
248673 differs from preserved248199; this is expected, not itself a blocker.

Provenance: research/2026-11-13-retail-http-contract.json. Activation evidence:
D:\Marathon-preservation\analysis\backend-settings-replay-20261113-184653.
Global JSON SHA1 matches its filename; manifest SHA1 does not. Preserve bytes
and provenance rather than inventing a digest relationship. Existing empty
aliases and SignOn protobuf fields remain unchanged. The completed candidate
run recorded no configuration GETs in available logs; coverage is incomplete.
Serving those URLs does not prove their discovery or client acceptance.
35 focused backend tests and29 reader/settings tests passed; no sign-in fix
has been demonstrated.

## Next work: preserve readiness/configuration contracts

Do not repeat the disproven error-code hunt, assume blocked WinHTTP, modify
entitlement IDs, guess protobuf fields, clear20, or force every later state.
The strongest remaining boundaries are independent provider readiness and
configuration discovery/application after successful session-reply processing.
Trace the configuration handoff and its inputs, including the call313ebc90 at
2fa1853b and consumers of the native stored configuration URLs/tokens. Establish
the required local manifest/configuration contract before changing the backend
or adding a preservation adapter. Dawn's separate readiness overrides and
config-getter/content-GET completion hooks are useful architectural references;
they are not drop-in Marathon offsets or proof of native completion.

No additional capture or test was launched in this analysis. The current
client may still be open from the user-run snapshot; do not close it without
considering the user's active session. Reader stops itself after its one read.


## Configuration-consumer follow-up

See configuration-contract-assessment.json and post-success-313ebc90.json in
D:\Marathon-preservation\analysis\signon-errors-20261113-193531.
313ebc90 is an optional host/port application path, not a configuration
blob downloader. Helper2f5d7740 copies a host string bounded64 and stores a
16-bit port. The previous suggestion to treat this call as the configuration
handoff is superseded.

Saved native consumer-12808 result-000002 hashes were verified. It contains
cfg_a at367c01f8 (success field14),cfg_b at367c01a8 (field15),cfg_c at367c0238
(field16), each with the backend's http://127.0.0.1/cfg_*/ value. Thus these
URLs reach native storage. Modeled refs:0d43c79c,0d442dbb,07ee3c0c. Canonical
callers/request initiation remain unresolved; the broad nearby-prefix reverse
search output is NOT a verified native call graph.

Confirmed backend gap: no content-manifest GET response or native manifest
encoder. Only SDR and direct-settings JSON are served; other GETs404. The
retail31424-byte .pb starts0100000000000000, no HTTP Content-Encoding; it is
not raw protobuf from byte0. Framing/encoding remains UNKNOWN. Do not claim
it is encrypted, use a guessed schema, or treat Dawn's37-byte GUID as a
verified Marathon format. Native session32-byte token, bootstrap16-byte
candidate and manifest identity are separate contracts.

Required backend work: native URL/identity discovery contract; compatible
manifest response for the preserved package inventory; exact request paths,
framing and validation; matching direct-settings name/hash documents. Current
known JSON endpoints work, but their discovery is not established. Missing
manifest support is confirmed; its causal role in the current state8 wait is
not. A readiness/configuration client adapter remains an allowed preservation
approach once exact getters/publication fields are identified. No new run,
state change, backend mutation or DLL deployment occurred in this follow-up.
