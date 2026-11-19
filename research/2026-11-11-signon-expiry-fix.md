# SignOn expiry wire correction from the Dawn comparison

The fresh PID 12808 capture establishes a concrete wire-contract mismatch:
success field 5 is **86400**, while top-level server time is **1794399239**.
The expiry value precedes the response's server time. Dawn's pinned HTTP route
passes an absolute epoch-seconds expiry to its serializer; Python passed the
24-hour lifetime itself. This mismatch is fixed in the Python server source.
The 08:37 EST manual retest delivered the corrected deadline but still stalled
at State 8. See the [retest and native configuration trace](2026-11-11-expiry-retest-and-native-config-candidate.md).

## Primary reference and captured evidence

Pinned Dawn commit: `57808bbc4aca5db9f4e04644b4b76803feb9c96b`.

- [server/http/server_http.cpp](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/server/http/server_http.cpp#L25)
  samples system-clock epoch seconds, then adds the configured token lifetime.
- [middleware/signon/response.cpp](https://github.com/isinternets/Dawn/blob/57808bbc4aca5db9f4e04644b4b76803feb9c96b/Dawn/src/middleware/signon/response.cpp#L67)
  writes that expiry argument as success submessage field 5 and the server
  time separately as top-level field 12.

Dawn's default lifetime is 3600 seconds. This fix preserves this project's
existing intended 86400-second lifetime; the corrected contract is an
absolute deadline rather than a relative duration. The checked Dawn source
names the argument expiry/expirySeconds. No recovered Marathon reader proves
its exact clock check yet, so this source contract must not be presented as
a demonstrated State 8 cause.

[consumer-pid12808-expiry-audit.json](consumer-pid12808-expiry-audit.json)
records the captured numbers, response hash and source hashes. All four
reader-result payload hashes and sizes verify. Raw packet/token contents
remain in the private analysis directory.

The same capture also establishes response consumption beyond HTTP: the
native token record's 32 bytes exactly match success field 4 of the received
SignOn reply. This supports one decoded-field publication, not acceptance of
every response field or completion of all dependent SOS actions.

The global/outer object is eight bytes before its native HTTP subobject.
The token pointer is at outer +0x1a4a0 (HTTP subobject +0x1a498); length and
capacity are both 32. The adjacent value 4 has no verified type or state
meaning and was not used to infer a terminal SignOn state.

The previously untyped `0x327c5cc4` consumer candidate is now ruled out:
fresh associated diagnostic text reads `E09031002M: Sound Output module error.`
It is an audio path, not an identified HTTP/SignOn consumer. It is excluded
from proposed patches. See the consumer follow-up for its earlier provenance.

## Source change and validation

`scripts/marathon_server.py` now samples the clock once per SignOn response:

```python
server_time = int(time.time())
token_expiry = server_time + SIGNON_TOKEN_LIFETIME_SECONDS
```

Field 5 receives the deadline; field 12 receives that same sampled server
time. `SIGNON_TOKEN_LIFETIME_SECONDS` is 86400. This changes the expiry value
without changing the intended lifetime or inventing other response fields.
At current timestamp widths the serialized reply grows by two bytes; a
281/282-byte response replaces the corresponding 279/280-byte response.
Total length alone is not a compatibility test.

The SignOn log now includes `server_time`, `expiry`, `lifetime_seconds` and
`expiry_contract=absolute_epoch_seconds`. After restarting the interpreter,
these fields verify the corrected response deadline without another memory
capture. They contain no session-token bytes.

`tests/test_signon_expiry.py` checks the actual encoded fields with a fixed
clock, requires exactly one explicit response clock sample, and checks that
reissuing after the first deadline yields a fresh future deadline. The full
targeted suite passed **80 tests in 4.35 seconds**. Existing native DLL
changes and their tests were not rebuilt or rerun for this Python-only fix.

```powershell
Set-Location D:\vault-breaker-preservation
$env:PYTHONPATH = "$PWD\scripts"
python -m pytest -q tests/test_signon_expiry.py tests/test_marathon_server.py
```

## Manual runtime retest

The capture helper was stopped after all requested snapshots verified; the
user was told Marathon could be closed. No agent game launch or UI action
occurred. The running server interpreter still holds the previous code;
changing its source does not reload it. At inspection, Python PID 27112 owned
the five expected listener ports. Its command line was unavailable to this
chat's Windows process query. The correction requires a server restart.

In the existing server terminal, stop the old server with Ctrl+C, then run:

```powershell
Set-Location D:\vault-breaker-preservation
python .\scripts\marathon_server.py --direct-settings-dir D:\Marathon-live\config\direct_settings
```

Keep that server window open. Launch Marathon manually and repeat sign-in.
Report whether it advances or remains stuck. The next log/capture comparison
must verify the new expiry is later than server time and then assess State 8;
it must not equate passing unit tests with a completed preservation goal.
