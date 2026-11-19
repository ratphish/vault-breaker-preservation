# HTTP result-consumer candidate audit: model-only negative result

Date: 2026-11-10. This scoped follow-up tested two proposed result-state readers
against the **prior synthetic text model**, with fresh saved capture bytes
overlaid where available. No live process access, game execution, production
edits or deployment occurred. Only this report was written.

## Finding

`3112F580` cannot currently be treated as Marathon's HTTP DWORD-state consumer.
It is one byte inside a REX.W-prefixed instruction on the modeled fallthrough
path. Correctly anchored, the instruction at `3112F57F` loads a **64-bit RCX**
value from `[RDX+450]`, whereas the proposed EOF store is a DWORD through RAX.
The same displacement does not establish the same object or type. The second
candidate, `0C191AD0`, really is a modeled DWORD read, but its object identity,
caller and result publication remain unproved.

Consequently this audit supplies no verified outer-worker copy of
state/bytes/status into a descriptor result or pending prefix, and requests no
additional runtime pages. The root investigation is independently following
the verified HTTP callback/EOF path.

## Inputs and evidence boundaries

- Model: `D:\Marathon-preservation\analysis\synthetic-text-section.bin`,
  851,977,728 bytes, mapped with file offset zero at RVA `1000` as specified by
  existing repository scripts. Its decoded instruction candidates are not
  authenticated current runtime code.
- Existing saved capture directory:
  `D:\Marathon-preservation\analysis\http-pid34652-offline`. Its manifest and
  range hashes were validated by `CapturedCode` from
  `scripts/trace_bootstrap_calls.py`.
- New saved capture:
  `D:\Marathon-preservation\analysis\http-handlers-34652-20261110-205438.json`.
  Its 21 ranges were independently checked for byte length and SHA-256, then
  overlaid **in memory** ahead of older ranges; no manifest or capture was
  rewritten. JSON SHA-256:
  `207935d1286e19827e8b498327b0998040727445871ae6e31e484e97cc6bf966`.
- Bounded stub resolution reused `trace_bootstrap_calls.trace`, with invented
  initial registers/flags and stack. It stops on non-stack memory, unresolved
  conditionals, or its instruction budget. A resolved modeled branch is not an
  observed runtime execution.

## Candidate 1: the REX prefix changes the purported state read

The model decodes this locally contiguous sequence:

```text
3112F55D  mov rdx,[rip+4061B7C]    ; static address 351910E0
3112F564  test rdx,rdx
3112F567  je 3112F572
3112F569  mov rdx,[rdx+8]
3112F56D  test rdx,rdx
3112F570  jne 3112F57F
3112F572  call 3156BB20            ; fallback, modeled protected call
3112F577  mov rdx,rax
3112F57A  test rax,rax
3112F57D  je 3112F5D2
3112F57F  mov rcx,qword [rdx+450]  ; bytes 48 8B 8A 50 04 00 00
3112F586  call 0778685D
3112F58B  ret
3112F5D2  add rsp,28
3112F5D6  ret
```

Starting the decoder at `3112F580` discards the `48` REX.W prefix and misleadingly
prints `mov ecx,dword [rdx+450]`. The predecessor's nonzero fallthrough and jump
target both select `3112F57F`, so that interior decoding is not a valid basis for
the proposed typed HTTP-state relationship. The global pointer and optional
`[pointer+8]` object are additional context boundaries, not identified HTTP
wrapper fields.

The bounded model of the call at `3112F586` resolves:

```text
0778685D -> 13948920 -> modeled adjusted-return target 0736DD1F
0736DD25 -> 31A11910 -> 308872C0
308872C0: mov edx,[rip+086F57A2]   ; first non-stack data read; stop
```

The initial three blocks are synthetic fallback bytes. `31A11910` and
`308872C0` use the fresh capture overlays. The final data read addresses RVA
`38F7CA68` under the captured image base; it requires real TLS/context state,
which this audit does not invent. No conditional path was chosen to pass that
boundary.

A separate **static modeled continuation**, not reached by this stopped model,
shows the following after recognizable TLS bookkeeping at `0736DD1F`:

```text
0736DD79  mov r8d,[rdx+458]
0736DD80  mov [rsp+20],rbx
0736DD85  lea rbx,[rip+31934153]
0736DD8C  and rbx,-10
0736DD90  movzx eax,byte [rbx+1A8]
0736DD97  not al
0736DD99  test al,1
0736DD9B  jmp 22478533
```

This introduces another field and protected dispatcher, but still supplies no
HTTP object identity, response pointer, status copy, pending clear or typed
result publication. It is not evidence to request a chain of unrelated VM
pages or to assign Dawn's structure offsets to Marathon.

## Candidate 2: modeled DWORD getter with unidentified object

The local modeled predecessor sequence preserves an instruction boundary:

```text
0C191AC3  add qword [rax+18],0B    ; preceding bookkeeping, not an HTTP field claim
0C191AC8  pop rbx
0C191AC9  pop rax
0C191ACA  popfq
0C191ACB  lea rsp,[rsp+8]
0C191AD0  mov eax,dword [rax+450]  ; bytes 8B 80 50 04 00 00
0C191AD6  add rsp,28
0C191ADA  ret
```

Unlike the first candidate, the actual modeled read is DWORD-sized. However,
RAX's object provenance is absent; there is no supported link to the callback
context whose modeled EOF path writes DWORD state 2. A matching displacement
and value width are insufficient. A bounded raw-byte scan of the synthetic
text found no E8/E9 rel32 target equal to exactly `0C191AD0` or `3112F580`.
That scan neither proves absence of callers nor establishes function entries:
protected calls, interior blocks and indirect dispatch remain possible.

## Decision

Drop the `3112F580` candidate from the HTTP consumer claim. Retain
`0C191AD0` only as an untyped modeled read awaiting independent caller/object
evidence. Do not infer completion, alter flags, copy a pending-result layout,
or request further pages on these candidates alone. The next justified
comparison remains the root's fresh EOF/state-store and dispatcher captures.
