# PID 34652: native WinHTTP callback and State 8

The user launched Marathon manually with observer v2 and supplied two fresh,
read-only captures. Their range sizes and SHA-256 hashes all verify; see
[the capture audit](http-pid34652-capture-audit.json). Main executable identity
matches the pinned build. No game launch, UI control, process suspension,
injection, or game-memory write was performed by the agent.

The run remains at State 8 in the inspected lmdetail session
`Tue_11102026_204258_0034652@x64_steam@76561198000001001@CA_04_39_56_5A_2F_EA14`.
At 20:44:26.591 local its state duration was 56,432 ms. Therefore the Steam
corrections alone have not demonstrated advancement in this run.

## Observed SignOn response path

Request handle `0x20a4e4fa4e0`, PID 34652:

| Local time | Native observation |
| --- | --- |
| 20:43:30.311–.312 | SignOn opened; native callback installed; 493-byte POST sent |
| 20:43:30.320 | QueryHeaders returned true, numeric HTTP status 200 |
| 20:43:30.320 | Two ReadData calls returned true; each requests 65,536 bytes and supplies a null byte-count output pointer |
| 20:43:30.320 | ReceiveResponse returned true on the same WinHTTP worker thread |

The reads and header query occur before the outer ReceiveResponse observer
returns. This establishes application response-handling activity beyond just
a successful send. The log is not evidence of an empty body: `reported_bytes=0`
is the observer's placeholder when the output pointer is null.

For asynchronous WinHTTP, actual received byte counts come through
READ_COMPLETE's length argument; a completed API return alone does not supply
that count. See Microsoft's
[callback contract](https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nc-winhttp-winhttp_status_callback).
The proxy has not replaced or intercepted the callback body, so it does not
yet directly log READ_COMPLETE length or native pending/state publication.

## Fresh callback identity and forwarding

The observed registration at caller RVA `0x3016f13a` supplies native callback
RVA `0x30619030`, all notification flags, and receives null previous callback
with error 0. Callback identity comes from this runtime call, not a guessed
bootstrap table.

The fresh 24-KiB callback capture authenticates its entry instructions:

- Saves handle, context, status and information arguments.
- Keeps the context from incoming RDX; skips delegation if it is null.
- Calls `0x314c92a0` with RCX=context, RDX=handle, R8=status, R9=information,
  and the original fifth information-length argument in the stack slot.
- Performs cleanup and returns.

This is static instruction evidence for the registered callback's delegation.
The header/read call sites actually observed in the log lie within the
captured `0x314c92a0` handler's region. The callback's small setup/cleanup
callees are not assigned semantic names without more evidence.

## Handler branches and the remaining protected-code boundary

Fresh instructions at `0x314c931a` compare the saved status to `0x80000`;
the equal branch targets `0x314cae7e`. This is the READ_COMPLETE case under
the Windows header's callback constants. The `0x20000` case targets
`0x314cad9e`, corresponding to HEADERS_AVAILABLE. The observed status query
returns at `0x314cade6`, and the observed read call returns at `0x2face8a2`.
The separate [wrapper audit](2026-11-10-native-http-wrapper-audit.md) records
the API table mappings and bounded return blocks.

Both cases enter protected out-of-window calls. Linear decoding through their
following `ret`/`int3` bytes does not establish a native fallthrough. An offline
model overlays the fresh ranges on the explicitly identified older synthetic
text and follows seven selected unconditional stub paths. It is retained at:

`D:\Marathon-preservation\analysis\http-pid34652-offline\callback-stub-model.json`.

The model identifies code pages for the status/header/read continuations but
stops at thread-local storage reads, conditional context, or unavailable data.
Its semantics outside authenticated ranges remain model evidence. It is not
a captured call stack or proof that a particular handler branch executed.
A focused 84-KiB user capture of 21 selected code pages was requested to
authenticate those candidate paths while this process remains open.

The model also exposed a harmless conditional branch to its own fallthrough.
`trace_bootstrap_calls.py` now follows it without inventing incoming flags:
both outcomes have the identical successor. A regression distinguishes this
from a real two-successor conditional, which still stops for missing context.
The earlier conditional fixture used a zero displacement and was corrected
to test a genuinely distinct successor. The focused capture/model suite
passes 10 tests.
The complete targeted Python suite passes 54 tests after these capture/model
changes. The installed native DLL was not rebuilt or replaced for this pass.

## What this changes

A blanket claim that no native HTTP callback runs is no longer a reasonable
explanation of this evidence: the application is querying status and issuing
reads from its native response-handler region. Exact asynchronous byte counts,
EOF delivery, native result publication, its consumer, and the State 8 task
dependency remain unobserved or unresolved. No HTTP response body, native
completion field, signature gate, service ID, or state advance was changed
based on the model.

Subsequent saved reads establish wrapper-level EOF and completion for the
identified SignOn request; see [the native completion audit](2026-11-10-native-signon-completion-proved.md).
That finding supersedes the earlier byte-count/EOF uncertainty above. The
outer worker, semantic response acceptance and State 8 dependency remain
unresolved. The temporary reader is now stopped at the user's request.
