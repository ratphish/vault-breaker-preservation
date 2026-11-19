# HTTP result-consumer follow-up after concrete wrapper identification

Date: 2026-11-10. Offline-only investigation. No requests were submitted to the
user-started read-only helper, no process was opened, and no production code or
DLL was changed. The user subsequently requested that the helper stop; no live
reads or additional capture requests are proposed here.

## Revised evidence boundary

The root investigation reports repeated fresh observations of the identified
SignOn HTTP wrapper at `0x7ff69b175b48` (image RVA `367a5b48`), with its request
handle and URL correlated to the actual SignOn request. It reports DWORD state
2 at `+450`, HTTP 200 at `+454`, and QWORD received count 280 at `+468`, plus a
freshly authenticated EOF-path state-2 store. These observations materially
advance the earlier model-only audit: the DWORD-state location now has a
concrete HTTP object association. This subtask did not independently reread
the process or print the saved response body.

The saved `result-000009.json` vtable is at `0x7ff6976f7620`, image RVA
`32d27620`; the root identifies slot 7 as native RVA `3136cdc0`. The root's
getter model connects it to the previously examined DWORD reader `0c191ad0`.
That replaces the earlier absence of ownership evidence for this getter;
complete fresh authentication of every protected stub remains distinct.

The outstanding consumer question is narrower: which outer worker reads that
state and publishes the caller-owned operation's byte count, status and pending
flag? This investigation did not establish that path.

## Global reference is modeled initialization, not the missing consumer

The saved `http-global-references-model.json` contains 71 reference candidates.
Its single direct LEA to `367a5b48` decodes in the prior synthetic model as:

```text
0781b09b  lea rcx,[rip+2ef8aaa6]    ; RCX = image_base + 367a5b48
0781b0a2  jmp 30416000
30416000  call 123b90bf
```

The bounded offline stub model resolves the latter through `0f1c12d1` to an
adjusted-return target `1df6eb3a`, then stops at the fresh TLS helper's first
non-stack memory access. A separately inspected **synthetic**, post-bookkeeping
payload is:

```text
1df6eb94  mov [rsp+8],rcx
1df6eb99  sub rsp,28
1df6eb9d  mov rax,[rsp+30]
1df6eba2  lea rcx,[rip+14db89b7]    ; static vtable RVA 32d27560
1df6eba9  mov [rax],rcx
1df6ebac  mov rcx,[rsp+30]
1df6ebb1  jmp 22478533
```

Installing a vtable in the target object supports an initialization role for
this modeled block. It is not an outer-worker result copy. The static vtable
RVA differs from the root's observed final derived vtable, so no complete
constructor/derived-type sequence is claimed.

Several references to neighboring `367a5b40` lead to other object contexts.
For example the `31a375cd` call's modeled payload tests `[rcx+1a4a0]`, while
the `31a37723` call's modeled payload returns `[rcx+1a4a0]`. Merely sharing a
global LEA does not supply a common typed HTTP descriptor.

## Virtual slot search did not identify a typed outer worker

A bounded raw-byte scan of the synthetic text found 749 occurrences of the
encoding `FF 50 38` (call through RAX slot 7). This count is a candidate count,
not decoded call coverage; some can be data or unrelated virtual interfaces.
Filtering immediate result comparisons produced one superficially relevant
state-2 example:

```text
327c5cb4  mov rcx,[rdi]
327c5cb7  test rcx,rcx
327c5cba  je 327c5cf6
327c5cbc  cmp dword [rsi],-1
327c5cbf  je 327c5cf6
327c5cc1  mov rax,[rcx]
327c5cc4  call [rax+38]
327c5cc7  cmp eax,2
327c5cca  jne 327c5cf6
327c5ccc  call 10ebb18a
```

The bounded model of the final call resolves via `10eaa46e` to adjusted-return
target `1873c2ae`, then again stops at TLS state. The separately inspected
synthetic continuation is:

```text
1873c308  mov rcx,rbx
1873c30b  mov dword [rbx+7c0],1
1873c315  jmp 22478533
```

There is no demonstrated link from this candidate's `[rdi]` object to the
identified HTTP vtable or SignOn wrapper, and no supported result-prefix copy.
It remains an unrelated-interface possibility and does not justify an extra
page capture by itself. The earlier `3112f580` candidate remains rejected as
an interior REX.W misdecode with a different object context.

## Outcome

The concrete wrapper and getter evidence now supports native HTTP state 2;
this is substantially stronger than a successful WinHTTP return. The outer
consumer's ownership, response-byte copy, pending clear and connection to SOS
remain unproved. No missing flag write or stalled callback is inferred from
that remaining coverage gap. No further live reads or page requests are
needed for this bounded subtask; all candidates and limits are preserved here.

## 2026-11-11: slot-7 candidate ruled out by fresh audio diagnostic

The root's saved PID-12808 consumer capture
`D:\Marathon-preservation\analysis\consumer-12808-20261111-071353`, result 4,
identifies the associated diagnostic at RVA `32f9e048` as
`E09031002M: Sound Output module error.` The `327c5cc4` slot-7/state-2
candidate above belongs to an audio path, not an HTTP result consumer. Discard
it from HTTP follow-up work. This is stronger negative evidence than the
earlier lack of typed HTTP provenance; the numerical vtable slot and state
comparison were insufficient to identify the subsystem.

## Additional bounded slot-7 candidate

An offline scan of indirect calls through slot `+0x38` also found synthetic
RVA `328fd11c`, followed by `cmp eax,2`. Its protected continuation at
`328fd122` models through return target `17433598` and stops at the TLS read;
the complete model is saved in `sos-slot7-328fd122-model.json` under the
private analysis directory. The later synthetic continuation around
`328fd14f` uses an object with fields at `+0x300` and `+0x305`, but neither
that object nor the virtual-call receiver is tied to the captured SignOn HTTP
wrapper. No execution or SOS ownership is established. Treat this as an
untyped candidate, not a fix target; the earlier audio false positive shows
why slot number and value comparison are insufficient.
