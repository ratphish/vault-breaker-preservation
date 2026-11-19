# Dawn SignOn responsibilities versus Marathon's copied session token

Date: 2026-11-11. Scope: public Dawn source pinned to
`57808bbc4aca5db9f4e04644b4b76803feb9c96b`, the repository source, and the root's
saved fresh-capture findings. No helper requests, process access, game or DLL
execution, UI actions, deployment, or production-code edits occurred.

## Finding

The root's exact match between the saved response's 32-byte session token and
the identified native object's stored bytes demonstrates consumption of at
least that SignOn response field beyond the HTTP transport. Dawn's reference
supports separating this step from server-side key generation, transport
completion, native terminal SignOn status, content configuration and BAP
activation. The checked Dawn source does not expose a native SignOn derived
class layout or a terminal-state enum that can classify Marathon's adjacent
fields.

No token bytes are reproduced here. The copied-token observation does not by
itself demonstrate that every response field was accepted, that SignOn reached
a semantic success terminal, or that downstream service activation completed.

## Preserve the two Marathon object bases

The root's saved session is
`D:\Marathon-preservation\analysis\consumer-12808-20261111-071353`, PID 12808,
image base `7ff704bc0000`. It reports HTTP context RVA `367a5b48`, eight bytes
after the enclosing/global base RVA `367a5b40`. Relevant offset translations:

| Observation | Relative to HTTP context `367a5b48` | Relative to preceding base `367a5b40` |
|---|---:|---:|
| String-like record begins | `1a490` | `1a498` |
| Observed heap pointer to copied token | `1a498` | `1a4a0` |
| Observed length 32 | `1a4a0` | `1a4a8` |
| Observed capacity-like value 32 | `1a4a8` | `1a4b0` |
| Adjacent DWORD value 4, meaning unknown | `1a4b0` | `1a4b8` |

This is a string-like layout observation, not identification of the exact
standard-library type or allocator. In particular, a scan for accesses to
`+1a4b0` without first identifying the base can mix a capacity-like QWORD with
an unrelated DWORD. **Value 4 is untyped adjacent data, not a discovered
terminal SignOn state.**

The root reports the HTTP object's state 2, HTTP 200 and transferred count 279
for this run, with a response of 279 bytes. It also reports that the saved
32-byte heap allocation exactly matches field 4 inside the response's top-level
field-2 success submessage. That session token is distinct from CommonInfo
field 3, which Dawn uses for a bootstrap content-id blob. This subtask did not
independently reread the running process or print saved secret material.

## What the pinned Dawn source actually owns

### Server state, response generation and client parsing are distinct

[state/runtime/state.h](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/state/runtime/state.h)
declares server-owned `SignOnState`: separate 16-byte encryption and
authentication keys, a 32-byte session token, relay endpoint and token lifetime,
plus a separate 16-byte bootstrap content token. `BapState` separately holds
the channel nonce, session key and envelope IV.

[state/runtime/state_runtime.cpp](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/state/runtime/state_runtime.cpp)
generates those secrets before publishing the complete local State. These are
the emulator's server-side fields; their C++ offsets do not describe the native
client's SignOn object. The bootstrap content-id token is later copied from the
installed client through
[bootstrap_token_publish.cpp](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/client/content/bootstrap/bootstrap_token_publish.cpp).
That direction is client content token to emulator State, unlike receiving a
session token from a SignOn reply.

[middleware/signon/response.cpp](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/middleware/signon/response.cpp)
encodes success fields 2/3/4 as encryption key, authentication key and session
token, with expiry, relay address and port following. It constructs the
CommonInfo bootstrap blob only when the separate content token is present.
It is a **response encoder**, not a replacement for the original native
client's protobuf consumer or terminal SignOn state machine.

[server/http/server_http.cpp](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/server/http/server_http.cpp)
routes SignOn to that encoder using its generated State and returns an HTTP
response. A source-level contract difference found before the expiry fix was:
Dawn computes success
field-5 expiry as current epoch seconds plus token lifetime, while the checked
pre-fix Python `handle_signon_request` directly supplied 86400. Marathon's receiver
semantics and any effect of this difference are unproved. The exact copied
token neither validates nor disproves expiry handling.

### Native transport readiness hooks do not identify terminal SignOn success

[signon_readiness_replacements.cpp](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/client/hooks/network/signon/signon_readiness_replacements.cpp)
calls the original predicates so native work still runs. While Dawn owns the
local path, it substitutes failure=false and ready=true; otherwise it returns
the original results. Its matching
[signature declarations](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/client/patterns/game/signon/signon_readiness_signature_bytes.h)
explicitly locate pre-SignOn transport predicates. They are not declarations
of the parser's terminal state or proof that an arbitrary neighboring DWORD
means semantic success.

The native target group in
[client/targets/game/network.h](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/client/targets/game/network.h)
publishes transport, HTTP, readiness, content-fetch/tick and content-token
addresses. It supplies no native SignOn derived-class member layout, decoded
API-key store, session-token destination, or terminal-state enumeration.
Absence from this inspected group is a bounded source finding, not a claim
that no other research or native implementation exists.

### Content configuration and secure BAP have their own activation contracts

[config_getter_answers.cpp](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/client/hooks/config_getter/config_getter_answers.cpp)
supplies a separate manifest URL and persistent GUID token. That GUID matches
manifest field 5 and is not the opaque 32-byte SignOn session token. The
[ContentConfig GET replacement](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/client/hooks/network/content_config/request/content_config_get_replacement.cpp)
publishes its own transfer/status fields and pending clear; external mode
delegates to the original native GET wrapper. These mechanisms do not locate
Marathon's SignOn consumer by themselves.

[server/bap/plaintext.cpp](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/server/bap/plaintext.cpp)
handles the later hello exchange and arms connection-owned crypto state after
constructing the complete response. Its pinned implementation accepts logged
hello shape/token mismatches, so it must not be described as strict token
authentication. The
[secure-channel envelope](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/middleware/secure_channel/envelope.cpp)
still uses the separate SignOn encryption/authentication keys to protect new
BAP key and nonce material. Copying a SignOn session token is one prerequisite
field-consumption observation, not evidence that the BAP bootstrap occurred.

## Evidence-backed next boundary

Keep the exact field match as a native semantic-consumption breakthrough.
Follow the actual token-copy producer and its callers to identify the derived
object base and any success/failure branches, then corroborate whichever state
field those branches actually write. For a putative terminal state, require
both a producer and a consuming decision on that same typed object. Do not
infer a state from nearby allocation metadata or copy Destiny offsets/enums.

The earlier `327c5cc4` virtual-slot-7/state-2 candidate is now explicitly ruled
out as audio in the amended
`research/2026-11-10-http-consumer-followup.md`, using the root's fresh
`E09031002M: Sound Output module error.` diagnostic. It is not an HTTP lead.

## 08:37 Eastern retest and next concrete source difference

The root's November 11 manual retest reports server PID 12816, client PID
23176, and a 281-byte response at 08:37:00 Eastern containing server time
1794404220 and expiry 1794490620. The server now encodes absolute expiry using
one clock sample. The client still remained at sign-in. This disproves the
claim that correcting this one wire difference alone was sufficient in that
retest; it does not make the original relative-expiry encoding correct or
establish which remaining dependency is blocking.

The strongest next reference difference is **CommonInfo field 3 in normally
activated Dawn**, as opposed to its default/uninitialized encoder state:

1. [client_hook_activation.cpp, lines 138–145](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/client/runtime/client_hook_activation.cpp#L138)
   requires `content::bootstrap::publish_token()` before installing game network
   hooks. Failure aborts that activation path. This is not an optional ordinary
   runtime omission.
2. [bootstrap_token_publish.cpp](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/client/content/bootstrap/bootstrap_token_publish.cpp#L15)
   reads the client's resolved 16-byte content-id token and publishes it into
   server State. The corresponding publisher sets `bootstrapTokenPresent=true`
   in [state_runtime.cpp](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/state/runtime/state_runtime.cpp#L369).
3. [response.cpp, lines 87–96](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/middleware/signon/response.cpp#L87)
   checks that flag, constructs the content bootstrap blob, and emits it as
   CommonInfo field 3. Its absence is the flag-clear/default encoding case,
   not the complete normal activated path shown above.
4. The checked Python server always omits CommonInfo field 3 and has no
   equivalent extraction/publication of Marathon's own content-id token.

The reference blob is built by
[signon_config_blob.cpp](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/middleware/signon/config/signon_config_blob.cpp):
little-endian header magic and entry key, a length-delimited **actual native
content token**, and terminator. The encoder source connects this responsibility
to deriving the client's content identity and later package validation. It
does not establish that Marathon uses the same key/layout or that this is the
State 8 gate.

The earlier 279-byte default-response alignment therefore establishes an
accepted transport/parser experiment; it is not proof that all normal Dawn
activation responsibilities have been reproduced. The correct next research
boundary is Marathon's CommonInfo/config application and own content identity,
with caller/reader evidence. Do not insert a fabricated 29-byte blob, copy the
Destiny token address, or infer a network dependency from the unrelated
29-byte XOR routine.

Other checked source differences are lower-priority research boundaries:
SignOn ownership IDs in Dawn are selected by its entitlement table, whereas
Python echoes the requested list; normal Dawn network activation additionally
installs content-config and investment hook groups before reporting installed
([network_hook_lifecycle.cpp, lines 53–60](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/client/hooks/network/lifecycle/network_hook_lifecycle.cpp#L53)).
These require Marathon-specific readers or service requests before they justify
implementation changes. No speculative production changes were made here.

## Exact Dawn content-token locator and blob, finite source audit

The pinned
[game_signatures.cpp, lines 85–91](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/client/patterns/game_signatures.cpp#L85)
identifies its config-init token-load sequence with this Destiny signature:

```text
0F 10 44 24 ? 41 B8 14 00 00 00 48 8D 15 ? ? ? ?
0F 10 4C 24 ? 48 8D 8C 24 ? ? ? ?
```

In
[game_network_targets.cpp, lines 19–22 and 56–61](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/client/targets/game/game_network_targets.cpp#L19),
the signed little-endian displacement at match+14 belongs to the LEA that ends
at match+18. The resolved source is `match + 18 + signed_disp32(match+14)`.
The resolver requires unique pattern matches before publishing its network
targets. Its general relative-address helper checks representable arithmetic;
the later bootstrap publisher separately catches an unreadable source.

`bootstrap_token_publish.cpp` copies **16 bytes**, as fixed by
`state::kBootstrapTokenSize`, and publishes them before network hooks activate.
The signature's `41 B8 14 00 00 00` happens to load R8D with 20, but that
instruction alone does not redefine the publisher's token size or establish a
Marathon token layout. The wildcarded token address keeps token bytes out of
the emulator source.

The exact reference blob is:

| Blob offset | Length | Encoding |
|---|---:|---|
| 0 | 4 | Little-endian magic `00123456`, bytes `56 34 12 00` |
| 4 | 4 | Little-endian token-entry key `007b620f`, bytes `0f 62 7b 00` |
| 8 | 1 | Token length varint 16, byte `10` |
| 9 | 16 | Actual native bootstrap content-id token; intentionally not printed |
| 25 | 4 | Zero terminator |

Total: 29 bytes. This is the bytes value of **top-level field 4, subfield 3**.
It is not success subfield 4's opaque 32-byte session token. The
[header](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/middleware/signon/config/signon_config_blob.h)
defines the size as 13 plus the 16-byte content token; the
[builder](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/middleware/signon/config/signon_config_blob.cpp#L35)
writes each component in that order.

Verification limits are important. The checked source locates the config-init
load, validates publication availability, and documents a native config
applier; it does not include a hook that reads back the native client's applied
content identity or independently demonstrates every downstream consumer.
The existing shipped-writer Unicorn probe in
`scripts/probe_dawn_signon_writer.py` supplies **synthetic** `bytes(range(16))`
when enabling its config flag. Its 310-byte enabled response corroborates the
writer's optional blob format, not the source of a Marathon token. The older
`scripts/check_dawn_fields.py` contains stale key-length guesses and supplies
no consumer evidence.

The finite review of existing Marathon research and relevant scripts found no
established corresponding token locator, authentic token extraction, or
CommonInfo-to-config-applier chain. Prior adjacent XOR-helper disassembly and
arbitrary dummy blob experiments do not fill that gap. This audit performs no
broad signature scan or process read and does not recommend applying the
Destiny pattern, key or token bytes to Marathon without matching native
producer/consumer evidence.

## Fresh Marathon key-dispatch correspondence, still no token source

The later saved session
`D:\Marathon-preservation\analysis\consumer-27072-20261111-0843`
provides a concrete correspondence that supersedes the earlier absence of a
key dispatcher. This subtask read saved JSON only; no live/helper request was
made. All six result-000002 ranges were checked for declared length and SHA-256.
The dispatcher page at image RVA `313e2000` has SHA-256
`eafc155a325993ba2d64c025485e65121e92137c32e4853f29f627171847798b`.

The exact fresh instructions include:

```text
313e28b7  cmp esi,007b620f
313e28bd  je 313e28df
313e28df  lea rdx,[rdi+26c0]
313e28e6  mov rcx,rbx
313e28e9  call 2feb7bb0
313e28ee  jmp 313e335c
```

Thus the same numeric entry key used by Dawn's bootstrap-token blob selects a
Marathon config destination `RDI+26c0` and a concrete reader. RDI's full object
identity and the source of its initial content remain unresolved. The root
separately reports a fresh magic comparison with `00123456`; numeric matches
support a shared configuration format, but this audit does not establish the
entire CommonInfo-to-dispatcher caller chain or that this branch executed.

Fresh result-000003 supplies the reader at `2feb7bb0`. It dereferences the
stream wrapper supplied in RCX, retains destination RDX, calls `3084e6d0` with
a stack QWORD output, and tests AL. If that call reports success, it passes
the resulting QWORD in R8 and destination in RDX to `31288500`, then writes a
zero byte at destination plus that QWORD. This is the shape of a
length-prefixed, null-terminating byte-string reader. There is no visible
fixed-16-byte or capacity check in this small reader; caller validation and
the two protected callees must be resolved before claiming exact semantics
or absence of bounds checks in the complete path. The success join at
`313e335c` sets AL to 1 before another protected continuation.

The adjacent fresh comparison tree contains keys `007b4687`, `007bbf51`,
`007b880a`, `007c272d` and `007c39fa`. Their protected branches do not provide
field names or types. Do not derive names from proximity or sorted numeric
order.

Supplementary **prior-model-only** stub resolution stops at the TLS helper's
first non-stack read. Static post-bookkeeping payloads suggest that `3084e6d0`
initializes a QWORD integer output to zero before dispatch, and `31288500`
retains R8 as a count and tests its destination. These observations support
the length/read hypothesis but are not authenticated runtime instructions
or complete decoder behavior. A narrowly targeted search for the exact
LEA-to-`+26c0` encoding found only the dispatch site; no typed getter or
native token initializer was identified.

This advances the candidate from a Destiny-only key to a fresh Marathon
key/destination/reader correspondence. It still does not supply an authentic
Marathon token, prove that a fake blob would pass content validation, establish
the branch's execution, or justify a production payload change.
