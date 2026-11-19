# Dawn bootstrap comparison and fresh Marathon capture

The investigation now prioritizes Dawn's actual bootstrap implementation and
the corresponding Marathon native contracts. Guessed Direct Settings JSON keys
are secondary until a consumer establishes their relevance.

## Reference identity

The installed Dawn 0.1.5.2 BUILD-INFO identifies source base
`57808bbc4aca5db9f4e04644b4b76803feb9c96b` plus `WAYPOINT-HOTFIX.patch`.
Its release targets Destiny 2 `86657.20.08.23.1800.d2_rc`. The source references
below are pinned to that base, not the moving production branch. This establishes
source behavior at the base; the local hotfix's complete diff and every installed
hook's actual execution have not been independently checked in this pass.

## Concrete bootstrap behavior in Dawn

1. [SignOn readiness replacements](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/client/hooks/network/signon/signon_readiness_replacements.cpp)
   call the native predicates, then return false for readiness failure and true
   for ready while their leases accept local SignOn. The corresponding
   [signature definitions](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/client/patterns/game/signon/signon_readiness_signature_bytes.h)
   explicitly identify these as **pre-SignOn** predicates. Marathon has already
   passed SignOn; these are not proof of a fix for the present post-SignOn wait.
2. The [content-config install group](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/client/hooks/network/content_config/lifecycle/content_config_hook_install.cpp)
   requires resolved HTTP enqueue, content fetch, content tick and manifest
   signature-gate targets. It disables the gate and installs enqueue/tick hooks.
   Copying only a SignOn serializer does not reproduce this group.
3. The [local GET replacement](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/client/hooks/network/content_config/request/content_config_get_replacement.cpp)
   implements an engine-facing asynchronous completion contract. In the Destiny
   ABI, transferred bytes are at +0, pending at +8, request status at +12, and HTTP
   status at +16. It writes status=2, HTTP status, transferred length, a memory
   barrier, and finally pending=0. The recognized local route receives an encoded
   manifest derived from installed package rows and entitlements. Unmapped local
   routes finish with HTTP 200 and **zero response bytes**, not `{}`. External-server
   mode instead calls the original enqueue function. The installed Dawn settings
   have external-server mode disabled.
4. The [tick replacement](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/client/hooks/network/content_config/tick/content_config_tick_replacement.cpp)
   reasserts the disabled signature gate and calls the original content tick. It
   leaves phase advancement to the native state machine.
5. The [optional config-blob builder](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/middleware/signon/config/signon_config_blob.cpp)
   really does encode the magic/token-key/token/terminator layout. That establishes
   a Destiny-side format, not its use or necessity in Marathon. Keep Marathon's
   omission until a Marathon consumer is traced. The November 11 retest still
   stalls at State 8; omission is not established as a successful bootstrap.
   Normal activated Dawn requires publishing the native token before its hooks
   install, as detailed in the newer SignOn consumption reference.

These are source observations. They do not authorize copying Destiny addresses,
structure offsets, signature bytes or mutation behavior into Marathon.

## Fresh Marathon evidence

The user captured PID 12348 at base `0x7FF6649D0000` into
`D:\Marathon-preservation\analysis\state8-pid12348`.
All eleven captured range hashes, the executable hash, base and image size pass
the offline auditor. PE SHA-256:
`d5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd`.
The before/after lmdetail copies name the same PID/session and state 8, duration
92,136 ms, updated at 16:10:55.832 EST. The reads occurred at 21:10:56 UTC.
This supplies session attribution and freshness despite filesystem mtime not
tracking each in-place lmdetail update. The capture is still sequential, not atomic.

The candidate entry's 16-KiB window is byte-identical to the older saved window.
The candidate check's local instruction bytes also match. Four captured callees
contain overlapping-instruction trampolines. Following their explicitly computed
local branch targets yields these edges, all in RVAs:

| Apparent callee | Locally recovered path | Continuation outside the fresh capture |
| --- | --- | --- |
| `0x0EA73F44` | LEA/push/ret to `0x0EA73F48`, jump to `0x0EA73F7B`, restore RBX | `0x2192BD16` |
| `0x224A0999` | call into `0x224A09A2`, jump through `0x224A09C6` to `0x224A09C9`, pop R13 twice | `0x058A48DF` |
| `0x198B4BF8` | LEA/push/ret to `0x198B4BFF`, jump to `0x198B4C2B`, restore R15 | `0x16ACB2AA` |
| `0x0C4E9E70` | register call to `0x0C4E9E7B`, jump to `0x0C4E9EAC`, restore R10 | `0x1ECEBC48` |

The older synthetic text image has return-address transformation stubs at those
continuations. For example, its `0x2192BD16` stub computes a signed delta of
`0xE2C81EC4`; applying that to candidate caller return `0x2EF4C7E5` gives
`0x11BCE6A9`. This is a static inference using synthetic bytes outside the fresh
capture, not an authenticated runtime edge. Importantly, ordinary call
fallthrough is not established. The `int3` at captured `0x2EF4070B` therefore
does **not** show that the alleged entry executes that trap or explain the wait.

## Immediate investigation order

1. Follow protected return-address dispatch before assigning meanings to the
   apparent calls or registers in the handoff. The old callback-table mapping
   remains unverified.
2. Map Dawn's local content route, request-completion contract and native content
   tick to actual Marathon callers/callees. Identify whether a request exists,
   who owns its completion, and what the corresponding native predicate reads.
3. Establish which differences belong to pre-SignOn readiness, SOS actions, or
   the subsequent manifest state. Do not apply an earlier-state fix to a later
   wait merely because both involve networking.
4. Only then implement a Marathon-specific change with a test tied to the
   recovered contract. No proxy or live game memory has been changed in this pass.
