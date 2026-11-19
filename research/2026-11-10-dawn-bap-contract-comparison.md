# Dawn and Marathon: BAP and content-completion contract comparison

Date: 2026-11-10. Scope: the user's `pasted-text-1.txt` handoff, the shipped Dawn
0.1.5.2 DLL, pinned public Dawn source, and the current Marathon proxy/server
source. No DLL or game execution, process-memory access, deployment, UI action,
or live-service connection was used for this comparison. The only executed
application code was the repository's Python codec/dispatcher, with an in-memory
fake socket and logging disabled.

## Main result

The repository implements the small BAP header codec and several placeholder
responses. It does **not** currently implement Dawn's authenticated BAP channel,
connection-owned crypto state, or request-specific service contracts. Dawn also
has a separate native ContentConfig completion path that is not supplied by
serving Direct Settings JSON. These are verified implementation differences;
none establishes that they cause Marathon's current State 8 wait.

Matching architecture is a useful way to identify responsibilities. Matching
service numbers, response lengths, log strings, or DLL size is insufficient to
establish Marathon wire compatibility or a playable activity.

## Artifact identity and source limits

| Artifact read | Bytes | SHA-256 |
|---|---:|---|
| `D:\Dawnv0.1.5.2\payload\steam_api64.dll` | 27,146,752 | `88c75ac8f411215a87a6e62758f9dcc34fb4bab903ebdec074c2e08164acc7c8` |
| `D:\Marathon-live\steam_api64.dll` | 212,992 | `e28a219f2a7d1d3a433a113fcebc468c4119cb48fd5c202ac619787be3ac2acc` |
| `D:\Marathon-live\bin\x64\steam_api64.dll` | 212,992 | `e28a219f2a7d1d3a433a113fcebc468c4119cb48fd5c202ac619787be3ac2acc` |

The two installed Marathon proxies matched each other when read. They contain
`http-bootstrap-observation-v1`; the checked Dawn DLL contains the
`ev=bap svc=25 rsp=26 result=ok` and manifest-served log literals, whereas the
checked Marathon proxies do not. String presence corroborates included code or
diagnostics; it does not establish execution or complete feature coverage.

`D:\Dawnv0.1.5.2\BUILD-INFO.json` names source base
`57808bbc4aca5db9f4e04644b4b76803feb9c96b`, patch
`WAYPOINT-HOTFIX.patch`, Release x64, MSVC v143 14.44.35207, and the matching DLL
hash above. It says the payload DLL was not rebuilt during packaging. No matching
hotfix patch was found by filename in the searched `D:\Dawnv0.1.5.2` and
`D:\Sunrise` trees. Consequently the public pinned source is a reference to the
declared base; it is **not** a verified exact reconstruction of the patched DLL.
Build-info's gameplay statement concerns accumulated Destiny waypoint fixes,
not Marathon compatibility.

The implementation details below come from source, not from decompiling every
corresponding shipped function. The root investigation separately holds REA Dawn
import evidence `ev_e5bd5d763dd05d727e746852f37362c7b238119dd9a4e5418b314ed232803f47`;
this report does not treat that import inventory as proof of every source path.

## Responsibility comparison

| Responsibility | Pinned Dawn base | Current Marathon implementation |
|---|---|---|
| Frame stream | Bounded ingress, coalesced-frame draining, partial-send staging, per-connection lifecycle | Python buffers incomplete/coalesced frames and uses `sendall`; no declared maximum frame/connection buffer |
| Outer header | Six bytes: magic, frame type, big-endian payload length | Same emitted header shape in `marathon_bap.py` |
| Inner correlation | Request service u16 + task u32; response adds status u16; notifications omit status | Codec supports these shapes, but listener always chooses correlated responses |
| Bootstrap | Service-26 authenticated key/nonce envelope derived from SignOn and BAP state | An 84-byte buffer containing big-endian 1 then zeros |
| Encrypted input | Authenticate/decrypt frame type 1 before decoding inner service | Frame type is decoded, then ignored; ciphertext is parsed as an inner request |
| Encrypted output | Seal inner reply/push with AES-GCM, frame type 1 | All listener replies default to plaintext frame type 0 |
| State ownership | Connection/authentication generations, directional nonces, validated state commits | SignOn session dictionary exists, but BAP listener passes no player and does not bind the socket to it |
| Service contract | Explicit response service, body codec, and reply/one-way/push mode | Several hand-written placeholders plus blanket `request_service + 1`, status 200 |
| Content completion | Separate URL/token getters, manifest encoder, GET-result publication, native tick | Proxy observes OS-level HTTP; external Python server supplies SignOn/JSON responses; no equivalent native manifest-result publisher identified in these sources |

## BAP contracts verified in Dawn's pinned source

The [frame codec](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/middleware/bap/bap_frame.cpp)
encodes the six-byte outer header and big-endian inner fields. Its
`encode_notification_payload` writes only service and sequence, without a status
field. The [service enumeration](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/middleware/bap/frame.h)
labels frame types 0/2 as plaintext and 1 as authenticated AES-GCM.

The [plaintext route](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/server/bap/plaintext.cpp)
echoes the **entire** service-30 body and preserves its plaintext frame type.
For service 25 it builds a genuine service-26 envelope. Important qualification:
this pinned source logs malformed hello shape or token mismatch but accepts
them; it must not be described as enforcing strict incoming SignOn-token
validation. It nevertheless publishes an authentication lifetime only after
encoding the complete response, resets prior authentication-owned state, and
sets directional nonces from BAP state. The receive nonce's last byte is XORed
with 1.

The [secure-channel envelope](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/middleware/secure_channel/envelope.cpp)
is 84 bytes: a big-endian length of 80, a 16-byte IV, 32-byte AES-CBC ciphertext,
and a 32-byte HMAC-SHA256. The encrypted plaintext is a 12-byte BAP nonce,
16-byte BAP key, and four `04` padding bytes. CBC uses the SignOn encryption key;
HMAC uses the SignOn authentication key over the first 52 envelope bytes. These
keys are distinct responsibilities from merely returning 84 bytes.

The [encrypted-frame implementation](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/middleware/secure_channel/encrypted_frame.cpp)
uses AES-128-GCM with a 16-byte tag **before** ciphertext. No AAD is assigned in
the checked implementation. Its nonce is a 12-byte little-endian counter. The
[encrypted runtime](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/server/bap/encrypted/encrypted_runtime.cpp)
requires an authenticated session, verifies/decrypts before parsing the service,
and consumes the receive nonce after successful authentication even if the
inner service is unsupported. It stages response encoding and state mutations;
send-nonce publication follows successful staging/commit. The
[reply encoder](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/server/bap/encrypted/reply/bap_encrypted_reply.cpp)
encodes the inner status-200 response, seals it, then emits outer frame type 1.

The [routing table](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/server/bap/encrypted/routing/bap_service_routing.cpp)
explicitly distinguishes correlated replies, uncorrelated pushes, and no reply.
Examples in **Destiny's pinned base**, not asserted Marathon service meanings:

| Service | Dawn reference | Python repository today |
|---|---|---|
| 8 | Uncorrelated-push route; no direct response; activity-message codec | Falls through to correlated service 9 status-200 response |
| 18 | Service 19 body `08 00 10 00`, two required protobuf varints | Two zero bytes |
| 23 | Service 24 echoes typed/count-qualified request identity and adds account SOID; defined empty answer | Membership u64 followed by UTF-8 display name |
| 16 | Service 17 echoes host u64, relay IPv4, neutral u16, port u16 (16 bytes) | IPv4 + port only (6 bytes); standalone CLI host is `0.0.0.0` |
| 110 | Explicit response 112 | Generic arithmetic produces response 111 |
| 29 / 171 | Explicit one-way, no response | Arithmetic response 30 / 172 |
| Unknown | Silent route, no inferred response number | Arithmetic response number + status 200 |

Body sources: [client config](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/middleware/bap/client_config/client_config_response.cpp),
[account translation](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/middleware/bap/account_translation/account_translation_response.cpp),
[activity host](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/middleware/bap/activity_host/activity_host_response.cpp).
The Python bodies are not implementations of these Dawn contracts. That is a
verified difference, not permission to replace them with Destiny bodies without
recovering Marathon readers and observed requests.

Local source anchors: `scripts/marathon_bap.py` functions `decode_outer_frame`,
`decode_inner_request`, `build_response_frame`; `scripts/marathon_server.py`
functions `dispatch_bap_request`, `handle_bap_connection` and
`create_objective_assigned_notification`. The latter's custom event-0x28 payload
and its tests establish local byte construction only. The checked TCP handler
does not call that notification constructor, and no demonstrated client reader
for this custom wire body is provided by these tests. Calling the object
`ActivitySession` or its notification authoritative does not prove a native
activity host or gameplay integration.

## Native HTTP completion and ContentConfig are separate contracts

Dawn's [HTTP worker completion](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/client/hooks/network/http/http_worker_completion.cpp)
publishes transfer counters, HTTP status, and wrapper request state 2 for its
native worker. Its [GET replacement](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/client/hooks/network/content_config/request/content_config_get_replacement.cpp)
publishes request-status 2, HTTP status and byte count, then clears the pending
flag with an interlocked operation after a memory barrier. This completes its
local manifest fetch; it is not merely a successful WinHTTP function return.
External-server mode instead delegates to the original native GET wrapper.

The [URL/token getters](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/client/hooks/config_getter/config_getter_answers.cpp)
supply a dedicated manifest URL and persistent 37-byte GUID token, matching
manifest protobuf field 5. The [manifest encoder](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/middleware/content/manifest/content_manifest_encoder.cpp)
emits entitlement definitions in field 2 and package descriptors in field 3.
These are raw protobuf, not the Direct Settings JSON documents.

The [tick wrapper](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/client/hooks/network/content_config/tick/content_config_tick_replacement.cpp)
reasserts its manifest-signature gate setting and calls the original tick; it
does not manufacture the native bootflow's next phase. The signature-gate and
result-prefix offsets are Destiny-specific and are not safe Marathon patches.

Dawn's [SignOn extended-field declaration](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/middleware/signon/extended/signon_extended_fields.h)
explicitly says the optional extended submessage and three config URLs have no
proven reader in its investigated client. They cannot be used as proof that
Marathon's SOS must fetch `/cfg_a/` or that arbitrary JSON keys create tasks.

The installed Marathon proxy's `completion=not_asserted` and
`async_callback=unmodified` diagnostics accurately limit their observation.
External server response bytes may still complete through Marathon's original
native worker: absence of Dawn-like result-writing code in the proxy does
**not** prove a broken callback. The root investigation's actual WinHTTP/native
object capture is the relevant way to establish that client-specific lifecycle.

## Reproduced local differences (no network or DLL execution)

An in-memory fake socket was passed to the existing `handle_bap_connection`;
`marathon_server.server_log` was temporarily replaced in that Python process
with a no-op, so no log files were written. Results:

1. Dispatch service 25 with empty body: 84-byte reply, first big-endian u32=1,
   all remaining bytes zero. Dawn envelope's first u32 is 80, with real keying
   material and authentication following it.
2. Dispatch service 30 with `bytes(range(20))`: input 20 bytes, output 12;
   reply is not an exact echo.
3. Feed `encode_outer_frame(bytes.fromhex('dead00000001') + bytes(30), 1)` to
   the listener: it returns a **plaintext type-0**, status-200 reply with service
   57006 (`0xDEAE`). Arbitrary encrypted-type input was interpreted as plaintext
   service `0xDEAD`; no prior authenticated session or valid GCM tag was required.
4. Direct dispatch of service 8 returns 9; service 110 returns 111.

These probes establish deterministic behavior of the Python implementation.
They do not exercise Marathon or prove that it has sent these service IDs.
Existing `tests/test_marathon_server.py::test_bap_service_dispatcher_flow`
asserts the placeholder lengths/body choices, not independent protocol
conformance or successful native consumption.

## Next evidence required

First correlate actual Marathon HTTP requests, completion/error status, native
worker state, and bootflow before changing service behavior. Separately, when
an actual BAP connection occurs, retain the complete stream's framing and
direction with secret material kept private; recover the exact Marathon
bootstrap and authenticated-envelope readers. Then implement a connection
state machine and independently validated codec vectors. Only after verifying
service semantics should individual response bodies or one-way/push modes be
implemented. No Destiny numeric mapping or offset has been copied into the
Marathon implementation by this investigation.
