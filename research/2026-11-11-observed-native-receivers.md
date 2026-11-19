# Observed native receivers, November 11

State 8 is **not resolved**. The actual SOS waiting task and its result pointer
remain unidentified. Do not substitute the HTTP response buffer for that result.

Private evidence: `D:\Marathon-preservation\analysis\receiver-trace-20261111`.
Current correlated run is PID 30440, image base `0x7ff72fbb0000`.
`current-runtime-30440.json` records State 8 at 15:57:35 EST, duration 168234 ms,
native HTTP state 2, HTTP 200, and 313 received bytes. The observed DLL hash is
`a81eb4dbae74c56be752dde0724c01fdbd3ec8ae7e5a53149c19ccb8ac15ba14`.
The pre-experiment DLL is preserved as `steam_api64.before.dll`.

## Actual SignOn call

The opt-in DLL observer clones the identified wrapper's vtable and forwards
each call through generated x64 stubs preserving integer/vector arguments,
flags, native stack arguments, and the original return address. It does not
write response/completion fields. Native tests verify integer, floating-point,
stack arguments, return values, and error preservation.

Repeated observed calls in PIDs 26196, 21576, 23468 and 30440 establish:

| Item | Observed identity |
| --- | --- |
| Native HTTP receiver | image + `367a5b48` |
| Request-start virtual method | slot 6, call at `304a8a7b`, return `304a8a7e` |
| RCX | identified native wrapper |
| RDX | actual SignOn URL on the calling worker's stack |
| R8 / R9 | request buffer / request byte count |
| Native stack argument at entry RSP+28 | response buffer, image + `367b5fd8` |
| Native stack argument at entry RSP+30 | capacity `a000` |
| Subsequent polling method | slot 10, call `30c286cf`, return `30c286d2` |

Fresh caller bytes confirm `call [rax+30]` and `call [rax+50]`, respectively.
The wrapper's recorded output pointer and capacity equal those actual stack
arguments. Full register and stack captures plus URL-adjacent metadata are
saved for PIDs 23468 and 30440. They do **not** establish Dawn's descriptor
prefix or pending/result layout in Marathon.

PID 23468's SignOn worker TID 25196 subsequently appears back in the same
worker-pool wait path as the other pool threads, with the SignOn call frames
absent. Its context and stack are in `waiting-contexts/contexts.json`.
Together with the completed wrapper, this directs investigation to the SOS
dependency rather than asserting that this HTTP request lacks native completion.

## Earlier callback-table interpretation fails runtime support

An additional bounded experiment observed entries in the four previously
alleged phase tables. Actual receivers include image + `34fb0a00`, `34fb0a28`,
`34fb0a50`, `34fb0a88` and `34fb0ab0`. Their first fields point to different
interior vtables in those regions; the following fields contain encoded byte
strings rather than an established phase-task/result structure.

For example, the entry at `32da1e70+7*8`, formerly labelled a Stage 7 callback,
executed during State 2. Its observed caller `30b83044` calls virtual slot 1;
the return at `30b83047` then passes RAX to a buffer operation with capacity
`100`, before further processing the same returned pointer. This supports a
string-related interface interpretation, not the previous enum-indexed callback
interpretation. Neither purported State 8 entry (IDs 35 and 67 in this
experiment) was observed during the captured State 8 transition or wait.
Absence of an observed call is bounded coverage, not proof of unreachability.
Do not patch these entries as an SOS fix.

## Reproduction and remaining requirement

Build `client_proxy\build_receiver_trace.bat` for only the identified HTTP
receiver. The explicit `tables` argument adds the separate candidate-table
experiment. Set `MARATHON_RECEIVER_CAPTURE_DIR` to an existing private evidence
directory before launching the isolated test client to save bounded entry
registers and stack snapshots. Default proxy builds enable neither observer.

Decode saved entries offline using `scripts\audit_native_receiver_trace.py`;
table captures require the recorded `--image-base`. The decoder checks the
saved caller against the native stack's return address and records file hashes.

The ABI executable passed. Existing native HTTP, callback ABI, Winsock ordinal
and transport regressions passed (`receiver-regression-build.log`). The focused
Python snapshot, completion-audit and read-only-reader suites passed 26 tests.
These are instrumentation checks, not evidence of a State 8 fix.

Completion still requires observing the **SOS task's own** receiver/result,
implementing the corresponding in-client producer/worker handoff with verified
Marathon fields, and demonstrating the same session leaving State 8. No such
completion writes have been made or claimed.
