# Audit of the failed deployed "Approach A"

Read-only audit after the user reported Termite. No game launch, process
attachment, state write, deployment, rollback, rebuild, or firewall change.

## Confirmed current implementation

client_proxy/marathon_bootflow_hook.h does not open, parse, decrypt, validate,
or publish a manifest. Its "manifest satisfied" message precedes a direct call
to image+3029126b. This is an advance bypass, not the proposed native local-GET
approach. scripts/advance_state8.py redirects the same alleged slot to the
same interior address and likewise does not supply manifest data.

Both deployed DLLs have SHA256
8b39afe884fabe17bd2660e7840e04bbefddc6226f2d310f08a318d35774f486:
D:\Marathon-live\steam_api64.dll and D:\Marathon-live\bin\x64\steam_api64.dll.
The experimental DLL remains deployed; audit did not silently change it.
Root steam_api64.baseline.dll has the earlier verified baseline hash
ba01f2fbf4175815883768e2efd7ff07e7c5c5d065b108b79c97eb7f928fefbf.
No Marathon process was running at audit entry. Firewall block is enabled
for all profiles; backend listening8080 belongs to PID16044.

## Actual latest run, PID10836

Proxy log timestamps are UTC on November14 (subtract5hours for Eastern):

* 19:02:20.533: Bootflow preservation worker started.
* 19:02:20.534: slot32da2e50 patched from image+30291240 to proxy hook.
* 19:02:33.869: provider state forced1->2 at000002825660e06c.
* 19:02:35.304: first SignOn request opens.
* 19:02:57.682 and19:03:07.958: later SignOn requests.
* 19:03:27.159: SteamAPI_Shutdown.

There are NO State8Tick-intercept, advance-call, advance-return or
advance-completed messages for this PID. Installation is not evidence that
the slot participates in the active bootflow or that the hook executed.

The new provider write occurs BEFORE HTTP initiation, without the earlier
five-second stable post-SignOn signature. The header checks state1/AppID,
but not completed HTTP, the task/result, the earlier flag/header signature,
or stability. It also calls a protected native pointer decoder on its helper
thread, unlike the prior private read-only decode. These are material changes
to the earlier controlled experiment. Their causal contribution is not proven.

Telemetry files telemetry_1794682962_65205.bin,
telemetry_1794682980_65207.bin andtelemetry_1794682995_65209.bin are tied to
PID10836 by their session identifiers and backend peer attribution. They
report reason hash1502254556 and error.content_manifest_not_provided, followed
by cleanup. requested_tasks0/remaining_tasks0 occur in the KTO event with
current_state ENUM(20). That does not establish a zero-task watchdog in
bootflow state8, nor the interpretation of EDX at30291240 as task count.
Do not derive numeric bootflow stages from a different world-controller enum.

## Unsupported control-flow assumptions

Earlier saved native data DOES contain a pointer from32da2e50 to30291240.
It does NOT establish that this pointer is a state8 tick slot or that
3029126b/0c4e9e70 advances bootflow. The existing November10 audit documents
the missing dispatcher/semantic evidence and protected control-flow limits.
Transport assertions do not verify an internal callback ABI, a bootflow enum,
manifest publication, or the safety of calling an interior instruction as a
standalone one-argument function. Do not activate Approach B on those claims.

## Backend status changed since the previous handoff

Current backend now has a content-manifest GET branch and changed cfg URLs.
Do not repeat the earlier statement that it has no manifest route. It serves
one31424-byte file for matching content_manifest/.pb paths. The repository,
live configuration and original retail-capture objects have identical SHA256
b4645834c7a8874ed56733186627f3ee16e3cf8809f84bc1e926415f44d9f907.
Thus this is still the captured retail body, not a demonstrated native-compatible
manifest for the preserved installation. Its framing/identity validation has
not been established. Presence on disk or an HTTP200 replay does not prove
that the engine received and accepted it.

## Next genuine Approach A boundary

Identify the actual native content-manifest URL/identity getter, GET/enqueue
entry, response owner and validated publication/completion predicate. A
local-file adapter must load compatible bytes into that owner and complete
the expected operation. Direct stage advancement does not implement it.

The error reason string is at modeled32da8838; hash598a95dc is initialized at
0c972c5a into the error record at3683d910/hash member3683d918. These are
registration anchors only, not recovered runtime failure-condition functions.
The focused references are saved in
D:\Marathon-preservation\analysis\bootflow-hook-audit-20261114.
