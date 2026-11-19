# Native SignOn HTTP completion: saved runtime evidence

The latest evidence moves the investigation above the native HTTP wrapper.
For an identified SignOn request in PID 34652, Marathon received all 280 reply
bytes, reached native completed state 2, and retained a wire-decodable
SignOn response. The same session still reports State 8 afterward. This is
not proof that the higher-level SignOn parser accepted the fields or that
the State 8 task consumed the result.

## Reproducible saved-data audit

[http-pid34652-native-completion-audit.json](http-pid34652-native-completion-audit.json)
records source-file hashes and the verified observations. Reproduce it without
any process access, UI, network or game launch:

```powershell
Set-Location D:\vault-breaker-preservation
$env:PYTHONPATH = "$PWD\scripts"
python scripts\audit_http_completion.py --session-dir D:\Marathon-preservation\analysis\readonly-34652-20261110-210219 --output D:\Marathon-preservation\analysis\native-http-audit-repeat.json
```

Use a new output filename; the auditor does not overwrite earlier evidence.
The input directory is the saved output of the now-stopped user-run reader.
That reader was pinned to the expected executable path/hash, PID and an
existing process handle. It never opened the process for writing. Its
`ended.json` confirms `stopped`; no further live reads or restarts occurred
after the user requested that it stop.

## Bound request identity

The latest correlated SignOn send in the inspected log is at **21:03:31.839
local on November 10**, request handle `0x20a4e4fae00`, POST length 527.
The saved native wrapper at `0x7ff69b175b48` matches that handle and length.
Its inline URL identifies `https://www2.signon.goliath.prod.gravityshavings.net/SignOn`.
This differs from the earlier request handle and server selected during the
same session; the evidence must not silently merge them.

A pointer in the saved WinHTTP handle record supplied a **candidate** context.
No private Windows structure offset was trusted by itself: the auditor binds
that candidate to the application's known request-handle field, URL, POST
length, response destination, response count and repeated native identity.
The object is inside the captured Marathon image, and its vtable contains
the native methods examined separately.

## Native fields and fresh code

| Native wrapper field | Saved value | Supporting evidence |
| --- | ---: | --- |
| +0x10 request handle | `0x20a4e4fae00` | Captured send code loads this field; matches the logged request |
| +0x428 POST length | 527 | Captured send code and corresponding runtime send log |
| +0x438 direct destination | `0x7ff69b185fd8` | Matched to the saved 280-byte buffer |
| +0x440 capacity | 40,960 | Buffer bounds checked against the saved byte count |
| +0x450 native state | 2 | Fresh EOF publication instruction writes this exact state |
| +0x454 adjacent status value | 200 | Matches the observed numeric HTTP-200 query; field producer is not independently traced here |
| +0x468 accumulated bytes | 280 | Fresh READ_COMPLETE code updates this count by callback length |
| +0x470 chunk-related field | 0 | Fresh READ_COMPLETE code writes this field; its value is consistent with a zero final chunk |

The fresh callback at RVA `0x30619030` delegates the original context,
handle, status, information pointer and length to `0x314c92a0`.
The fresh handler's READ_COMPLETE branch reaches authenticated protected
continuation code at `0x0db21403`. It records the chunk length, increments
the accumulated count for nonzero chunks and branches on zero length.

The authenticated EOF continuation contains this instruction at
RVA `0x06333c1f`:

```text
mov dword ptr [rax+0x450],2
```

Its bytes, the adjusted-return stub and the shared dispatcher were read
before the reader stopped and retained in `result-000001.json`. The
standalone auditor requires the exact state-store bytes from that fresh
capture; an old synthetic copy does not satisfy the check.

Saved results 7 and 8 repeat the same wrapper identity, state, status and
counters. Destination length equals the accumulated 280 bytes and fits its
capacity. The body is retained **privately** in the analysis directory; the
repository audit exposes its SHA-256 and wire-field sizes, not keys/token.
Its SHA-256 is
`db30a396e03df9e435db2bcfd4c2269029b63258500704f7f86aeb2bd7d1deea`.
The wire decoder finds top-level error 0 and success submessage length 217.
Those wire facts do not prove semantic acceptance by Marathon's consumer.

An archived lmdetail read after the helper stopped identifies this same
PID/session at State 8, updated **21:16:26.145 local**, duration 1,975,986 ms.
It is saved as `lmdetail-after-reader-stop.json` in the private session
directory. No State 9 transition was established.

## What the Dawn comparison now establishes

Dawn's native HTTP replacement explicitly publishes the finished request
state and transferred bytes. Marathon's original Windows-backed path also
publishes an EOF/finished state and transferred bytes for this request.
The layouts differ: Dawn's documented wrapper offsets must not be copied
into Marathon. The useful architectural match is the separation between
transport, native wrapper completion and higher-level result consumption.

The conjecture that the current stall is simply caused by a missing native
HTTP completion is contradicted for this identified request. Implementing
a fabricated pending clear in the proxy would bypass the consumer we still
need to understand. The next legitimate target is the outer worker/SignOn
consumer and its State 8 dependency.

The native wrapper's captured vtable has slot 7 at RVA `0x3136cdc0`. Its
fresh entry plus modeled protected continuations link it to the previously
untyped +0x450 DWORD getter at `0x0c191ad0`. Relevant continuation pages
were subsequently authenticated by the stopped reader. This supports the
getter's HTTP ownership, but does not observe which outer task invoked it.
The [consumer follow-up](2026-11-10-http-consumer-followup.md) distinguishes
untyped slot-7 candidates from a verified higher-level caller.

## Bounds and unresolved work

These were sequential saved reads, not an atomic CPU-context snapshot.
The callback event sequence itself was not logged. The state-2 observation
and the fresh EOF-path instruction are separate evidence, not a direct event
trace proving which invocation performed the store.
The matching request identity/counters, received body and fresh handler code
support the wrapper-level finding. They do not establish the outer result
pointer, its pending-bit publication, protobuf field-consumer behavior, a
ContentConfig dependency, BAP readiness, or the actual State 8 predicate.

The read-only helper is stopped at the user's request. Offline analysis
continues from saved bytes only; missing fresh code/data is not filled with
claims about executed synthetic-model paths. No production proxy, service
response, native field, signature gate or state advance was changed during
this completion audit.

Validation of the saved-data auditor and related capture/server controls:
73 Python tests passed, plus all 5 offline protected-call model tests. The
auditor's negative controls reject altered bytes/hashes, mismatched request
handles, a non-SignOn route, changing counters, missing fresh EOF code and a
non-completed state. They explicitly prevent a wrapper-level result from
being promoted to semantic SignOn acceptance or a State 8 root-cause claim.
All successful range hashes in the stopped reader's 14 saved results were
checked; [the session audit](http-reader-session-audit.json) records their
provenance without embedding raw reply/key/token bytes.
