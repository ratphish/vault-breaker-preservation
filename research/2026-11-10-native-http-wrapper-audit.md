# Fresh Marathon HTTP wrapper audit

Date: 2026-11-10, America/New_York. Read-only analysis of the saved capture
`D:\Marathon-preservation\analysis\http-completion-34652-20261110-204352.json`.
No live process access, game launch, UI action, deployment, or production-code
edit was performed. Only this report was written.

## Result and limits

The four supplied executed-call return addresses are backed by exact indirect
call instructions in the fresh capture. They resolve through the captured
native HTTP function table to the proxy observers for SendRequest,
ReceiveResponse, QueryHeaders and ReadData. Their immediate continuations test
the returned BOOL. The available bytes do **not** establish a higher-level
result-prefix publication, pending-flag clear, complete response byte count,
or SOS task completion.

Several continuation calls leave every captured range immediately. They must
remain unresolved; linear disassembly across the protected fragments produces
plausible-looking unrelated instructions and cannot recover their behavior.
No old synthetic-text image was read or used as runtime evidence.

## Capture identity and verification

The JSON file SHA-256 is
`4c937177a5db165564a427910c136378f9711cd721878716688f032e85ce383b`.
Its metadata reports PID 34652, image base `0x7ff6649d0000`, executable SHA-256
`d5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd`,
status `complete`, and no capture errors. The capture interval is
2026-11-11 01:43:53.097106–01:43:53.664278 UTC, or November 10
20:43:53 Eastern. Metadata limitations explicitly state that sequential reads
are non-atomic and import-target identity does not establish execution.

All seven range lengths and SHA-256 values were independently recomputed from
their JSON `hex` bytes and matched:

| Range label | Start RVA | Length | Verified SHA-256 |
|---|---|---:|---|
| winhttp_wrappers | `311c0000` | 196608 | `26934ce31cc400aada18a6fa62aa82e76440c49f6f8639c202c19a21ccfadd09` |
| winhttp_function_table | `3530a800` | 256 | `b0a7de47d6d5d17d90e41a35aaee1f7a9a7a9fa65282c8f7242469250da0d486` |
| winhttp_receive_worker | `3115c000` | 24576 | `05f7525c3fd7771d3edaac0ab4351738e42160a8d35b6ef94d37807d693b4d21` |
| winhttp_initialize | `3016e000` | 16384 | `df624d662d82cb353eafb0f1522e5b9e63eb067f2d46255b6cc2094cba8654fd` |
| winhttp_response | `314c8000` | 16384 | `88d44c7cfa5b0202c5a0f669d8980aba777970730aa3542f49910944fc3d91de` |
| winhttp_read | `2facd000` | 16384 | `4f93e425891afe7304041592992533565b5d3e170a143911cbc1b836b1cdae5c` |
| winhttp_available_thunk | `31be2000` | 8192 | `2002cc504f69b5176ce77a9998474f4fa71d747393d7934335243170d9ec3cbf` |

Verification used Python `bytes.fromhex`, a length comparison, and
`hashlib.sha256`. Capstone decoded instructions only from explicit anchors
below. Runtime execution attribution for the four return addresses comes from
the root investigation's supplied v2 observer logs; this saved JSON itself
records bytes and table values, not an execution trace.

## Call edges backed by exact bytes

The module inventory places the proxy at base `0x7ffdf39d0000`. The table values
and call-site displacement calculations agree:

| API attribution from supplied logs | Call RVA | Exact instruction bytes | Table slot RVA | Captured target | Proxy RVA |
|---|---|---|---|---|---|
| WinHttpSendRequest | `311dd693` | `ff15b7d11204` | `3530a850` | `7ffdf39d5e70` | `5e70` |
| WinHttpReceiveResponse | `3115d2f3` | `ff155fd51a04` | `3530a858` | `7ffdf39d5e00` | `5e00` |
| WinHttpQueryHeaders | `314cade0` | `ff157afae303` | `3530a860` | `7ffdf39d5c70` | `5c70` |
| WinHttpReadData | `2face89c` | `ff1576bf8305` | `3530a818` | `7ffdf39d5d60` | `5d60` |

For each call, slot RVA = return RVA + signed little-endian disp32. In
particular the supplied return RVAs are exactly six bytes after these
instructions, not approximate function labels. The table targets are observed
values, while API naming depends on the correlated observer evidence; no
unrecorded WinHTTP export lookup was performed in this audit.

### ReceiveResponse

```text
3115d2f3  call [3530a858]
3115d2f9  test eax,eax
3115d2fb  je   3115d2ff
3115d2fd  jmp  3115d332
3115d2ff  call 1e350798       ; outside all seven captured ranges
3115d304  nop
3115d305  call 142c0e92       ; outside capture
3115d30a  ret
3115d332  call 061f6dd6       ; success continuation, outside capture
3115d337  ret
```

Both BOOL branches have explicit out-of-capture protected continuations. None
of these anchored instructions publishes a result flag or byte count.

### QueryHeaders

```text
314cade0  call [3530a860]
314cade6  test eax,eax
314cade8  je   314cae46
314cadea  call 1a1e4281       ; nonzero return, outside capture
314cadef  ret
314cae46  call 1329d990       ; zero return, outside capture
314cae4b  nop
314cae4c  call 0cd8a21a       ; outside capture
314cae51  ret
```

The log-reported HTTP 200 is response-header evidence. This wrapper does not
contain a reachable, fully supported completion publisher in the shown block.
The semantic meaning of the protected continuations remains unknown.

### ReadData

```text
2face89c  call [3530a818]
2face8a2  test eax,eax
2face8a4  jne  2face8d3
2face8a6  call 05a81e91       ; zero return, outside capture
2face8ab  nop
2face8ac  call 120a6467       ; outside capture
2face8b1  ret
2face8d3  add rsp,38
2face8d7  ret
```

The nonzero branch reaches a stack-unwind/return block directly. It does not
read a synchronous byte-count output in this continuation. That is consistent
with the supplied logs' null ReadData output-counter and asynchronous callback
configuration; it does not identify the callback's final-result writes.

### SendRequest

```text
311dd693  call [3530a850]
311dd699  test eax,eax
311dd69b  je   311dd6b8
311dd69d  call 30e019d0       ; nonzero return, outside capture
311dd6a2  call 1a334fd1       ; outside capture
311dd6a7  call 311d0f5b       ; inside wrappers range
311dd6ac  pop rsi
311dd6ad  pop rbp
311dd6ae  ret
311dd6b8  call 053b2d44       ; zero return, outside capture
311dd6bd  nop
311dd6be  mov [rsp+4c],eax
311dd6c2  call 1e6c1619       ; outside capture
311dd6c7  ret
```

The captured callee `311d0f5b` begins `push rdx; jmp 30313749`; the jump target
is outside capture. The only explicit store in the shown failure continuation
is to stack slot `[rsp+4c]`. Calling it a particular HTTP error/result field is
unsupported without resolving the preceding protected call and caller frame.

## The internal availability slot is not an identified WinHTTP export

Table slot `3530a820` contains `0x7ff6965b27e7`, i.e. Marathon RVA `31be27e7`,
rather than a WinHTTP or proxy address. Its captured entry is:

```text
31be27e7  call 0a5b0675       ; outside capture
31be27ec  call 31bebe36       ; outside 31be2000..31be4000 window
31be27f1  pop rbp
31be27f2  ret
```

A byte-pattern candidate at `3115d29d` calls this slot and tests EAX; that site
was not one of the four supplied executed-call anchors. It must not be labelled
a verified QueryDataAvailable invocation, a constant-success stub, or the
operation responsible for the two observed reads.

## Comparison to Dawn's native completion contract

Pinned base: `isinternets/Dawn` commit
`57808bbc4aca5db9f4e04644b4b76803feb9c96b`. This is a reference implementation
for a different client, not a source map for Marathon.

Dawn's [HTTP descriptor routing](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/client/hooks/network/http/http_descriptor_route.cpp)
explicitly interprets its native descriptor and writes into caller-owned
response storage. Its [worker completion](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/client/hooks/network/http/http_worker_completion.cpp)
sets downloaded-byte count, HTTP status, transfer-rate fields, and wrapper
request state 2. Its separate [ContentConfig GET replacement](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/client/hooks/network/content_config/request/content_config_get_replacement.cpp)
writes request status and HTTP status, atomically publishes transferred bytes,
then clears pending after a memory barrier. Those source statements identify
the responsibility being sought; their byte offsets cannot be assigned to a
Marathon object from this wrapper capture.

These fresh Marathon anchors establish OS-API invocation and BOOL handling,
not the same higher-level descriptor/result fields. No captured, supported
path in this audit identifies which Marathon object owns pending/completed
state, where it copies actual response bytes, or how it notifies SOS. A broad
search for matching numeric offsets in obfuscated instruction candidates would
not establish that relationship.

## Meaning of the supplied nested-call log order

The root's supplied context reports one SignOn request handle
`0000020A4E4FA4E0`, HTTP 200, QueryHeaders followed by two ReadData calls with
null output-counter, before ReceiveResponse returns 1. Those observations are
compatible with nested callback-driven reads. They do not independently prove
a callback failure or that final body EOF was delivered.

[Microsoft's ReadData contract](https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpreaddata)
requires a null byte-count pointer for asynchronous use. READ_COMPLETE supplies
the count; an asynchronous zero-length READ_COMPLETE indicates response EOF.
Completion can occur synchronously and invoke a callback that starts another
read before an outer call returns. Consequently request/return log order alone
cannot establish the native caller's state when all callbacks finish.

The known callback RVA `30619030` is outside every captured range. Its
[WinHTTP callback contract](https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nc-winhttp-winhttp_status_callback)
can correlate request handle, context, status, buffer and actual byte count.
The root's pending callback-window capture is the appropriate next evidence:
identify READ_COMPLETE/REQUEST_ERROR branches and the native state stores,
then compare them with the wrapper/result ownership actually observed in
Marathon. This report stops at that missing boundary and supplies no proposed
offset writes or patches.
