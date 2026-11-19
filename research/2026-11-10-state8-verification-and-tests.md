# State 8 evidence correction and manual test procedure

The handoff does not establish the State 8 dispatch path or a working Direct
Settings schema. This pass verified the saved bytes, corrected analysis and
transport code, and prepared tests. It did not launch the game, use UI control,
attach to a process, change the proxy, or change either directory's JSON files.
No claim is made that State 9 is reached.

## What the saved evidence establishes

Reproducible output: `state8-static-path-audit-20261110.json`, generated with:

```powershell
Set-Location -LiteralPath 'D:\vault-breaker-preservation'
python .\scripts\audit_state8_evidence.py --dump-dir 'D:\Marathon-live' --pe 'D:\Marathon-live\Marathon.exe' --image-base 0x7ff70f850000 --synthetic-text 'D:\Marathon-preservation\analysis\second-worker-text.bin'
```

This only reads files. `--output` accepts a new filename and refuses to overwrite.
The synthetic text image has SHA-256
`1c8f2a6e3cc77ad5b373afb368959968c78e571706974db051a32fabd0af459e`.
Its model assumptions remain limitations; corroborating saved bytes does not
turn a synthetic image into an authentic execution trace.

| Handoff claim | Verified observation and consequence |
| --- | --- |
| Four arrays are Init/Update/Exit/Advance indexed by bootflow state | No dispatcher connecting an enum to those arrays was supplied or recovered. Proposed Table 3 slot 16 is `0x0000003A656E6F4E` (`None:`), not a code pointer. It cannot be treated as the claimed contiguous callback array. |
| `0x302832A0` is State 9 Exit | Saved bytes write `0x32DA2CA0` into `[rcx]`, test `dl & 1`, conditionally call with `edx=0x30`, and return the object. This is consistent with a deleting destructor and a vtable. The interpretation as a specific bootflow callback is unproved. |
| `0x30291240` waits on task counts | It tests signed `edx`, and on `edx <= 0` returns incoming `r8` via `r9`. The positive path calls four candidate targets. Nothing in these bytes identifies EDX as a task count or ties it to telemetry. |
| Call at `0x3029124C` counts completed tasks | The saved `E8 4C 6D FF 41` resolves to RVA `0x72287F9D`, outside PE SizeOfImage `0x39D3E000`. Memory mapping and callee behavior are unknown. This is not sufficient evidence of a valid task counter; an external thunk or protected-code mechanism has not been ruled out. |
| Call at `0x3029126B` advances to Stage 9 | The bytes resolve to RVA `0x0C4E9E70`. No callee side effect or connection to the stage enum is established. Previous scripts stopped at the first `ret` and missed this branch target; the new auditor follows it. |
| `0x2EF4C7E0` invokes the adjacent XOR helper | It calls RVAs `0x0EA73F44` and `0x2EF4070B`, then executes `pop rbp; ret`. It does not directly call the helper at `0x2EF4C7F0`. The helper's 29-byte comparison does not establish a SignOn field or session-integrity role. |
| Zero requested/remaining tasks causes the wait | The historical lmdetail file reports state `8`, duration `117630`; this corroborates the historical wait. It does not identify a register's meaning or establish causation. |

All addresses above are RVAs. The old absolute VAs depend on a recorded/assumed
capture base of `0x7FF70F850000`; never reuse that base for a new process.
Old dumps have no capture manifest and mixed modification times, so they are
not an atomic, independently authenticated State 8 snapshot.

Static syntactic anchors in the synthetic text are retained in the report:

- `0x0A75D825`, `0x132FED23`, `0x17EDAF8F` reference URL format RVA
  `0x32D28FC8`; their local paths reach protected dispatcher `0x22478533`.
- `0x0C97344C` references `error.sos_prelaunch` at `0x32DA8F28` and stores its
  address into a global. This is an error-registration anchor, not SOS execution.
- `0x10763DF7` and `0x16BD1055` reference the alleged Update/Advance tables,
  respectively. Local bytes do not demonstrate state-indexed dispatch.

## What is known about settings

The dump writer in `client_proxy/steam_api64_diag.cpp` writes settings regions
from **named RVA minus 0x200**. Thus `mem_direct_settings_32D28F30.bin` starts at
`0x32D28D30`, not `0x32D28F30`. The corrected string addresses are:

| RVA | String |
| --- | --- |
| `0x32D28E20`, `0x32D28E28`, `0x32D28E38` | `merge@`, `replace@`, `delete@` |
| `0x32D28EA8` | `global` |
| `0x32D28EB0` | `activity_local_client` |
| `0x32D28EC8` | `activity_synced_client` |
| `0x32D28EE0` | `commerce_catalog` |
| `0x32D28EF8` | `mailbox` |
| `0x32D28F00` | `pes_rules_engine` |
| `0x32D28F58`, `0x32D28F70` | `config\direct_settings\`, `.json` |
| `0x32D28FC8` | `%s/direct_settings/%s/%s.json` |

These establish names and path components, not a complete JSON schema or merge
semantics. No recovered consumer proves `services`, `features`, `client_settings`,
`activity`, or SOS task registration keys. The expansion of SOS to “Start Of
Session” also remains unverified here. Dawn's `payload/Dawn/settings.json`
configures Dawn itself (root keys `version/core/steam/experiments/client/server/state`);
it is not evidence of Tiger's document schema.

## Code changes

- `scripts/direct_settings.py` serves from one explicit directory, validates
  JSON syntax (including rejecting duplicate keys and NaN/Infinity), and preserves
  valid bytes verbatim. It does not claim to validate Tiger's schema.
- `scripts/marathon_server.py --direct-settings-dir PATH` applies that directory
  to ports 80/443/8080/8081. Default is repository `config/direct_settings`.
  The previous implicit repository/live/CWD search could silently shadow edits.
- Missing documents now return 404; invalid/unreadable documents return 500.
  There is no fabricated successful `{}` fallback. GET/HEAD status, length and
  SHA-256 header agree. Logs include source, digest and User-Agent, making
  manual probes distinguishable. HTTP requests alone still do not prove process
  attribution or that the game parsed the content.
- SignOn Field 4.3 remains omitted and its three existing URLs remain unchanged.
  A regression test checks the fields themselves, not only total payload length.
- `audit_state8_evidence.py` follows local branches, records exact source hashes,
  flags out-of-image call targets, uses the corrected settings dump offsets,
  and rejects mixed/tampered files when a capture manifest is present.
- `capture_state8_evidence.py` is supplied for **you** to run. It opens an existing
  PID with QUERY_INFORMATION/VM_READ only, verifies the executable path, gets its
  actual module base, and reads eleven bounded ranges (177 KiB total).
  It never starts a process or writes its memory. A new output directory and
  a timestamped hash manifest are required; incomplete reads fail explicitly.
  It does not suspend threads, so reads are sequential rather than atomic.

Validation performed here: saved-file analysis, Python AST syntax parsing, and
`git diff --check`. Pytest, HTTP listeners, and live-process capture were left
for you to run. Existing unrelated dirty work was preserved.

## Exact tests for you to run

Use 64-bit Python 3.11+ with `pytest` and `capstone` available in that interpreter.

1. Run the focused regressions, with no game running:

```powershell
Set-Location -LiteralPath 'D:\vault-breaker-preservation'
$env:PYTHONPATH = (Join-Path (Get-Location) 'scripts')
python -m pytest -q .\tests\test_direct_settings.py .\tests\test_state8_evidence.py .\tests\test_marathon_server.py
```

Expected: all pass. Tests use temporary files and temporary loopback ports;
they do not launch the game or the service daemon. The existing server logger
may append to the repository's `marathon_server.log`.

2. In a separate PowerShell window, start the server with an explicit source:

```powershell
Set-Location -LiteralPath 'D:\vault-breaker-preservation'
python -u .\scripts\marathon_server.py --direct-settings-dir 'D:\Marathon-live\config\direct_settings'
```

Expected startup line: `Direct Settings root: D:\Marathon-live\config\direct_settings`
(path capitalization can differ). Use Ctrl+C to stop this instance when finished.
Do not start a second daemon over an already running instance.

3. In your other PowerShell window, verify transport independently of the game:

```powershell
$url = 'http://127.0.0.1/cfg_a/direct_settings/global/global.json'
$response = Invoke-WebRequest -Uri $url -UserAgent 'preservation-manual-probe'
$response.StatusCode
$response.Headers['X-Direct-Settings-SHA256']
(Get-FileHash -LiteralPath 'D:\Marathon-live\config\direct_settings\global.json' -Algorithm SHA256).Hash.ToLowerInvariant()
$head = Invoke-WebRequest -Method Head -Uri $url -UserAgent 'preservation-manual-probe'
$head.Headers['Content-Length']
$response.Headers['Content-Length']
curl.exe --silent --output NUL --write-out '%{http_code}' 'http://127.0.0.1/cfg_a/direct_settings/global/__missing_state8_probe__.json'
```

Expected: status 200; both digests equal; HEAD and GET lengths equal; final code
404. A successful response containing `{}` proves only that the existing stub
was served, not that settings initialized tasks.

4. If you choose to make a new client run, launch and operate the isolated
client yourself. While it is stably at the title screen, capture it:

```powershell
$gameProcess = @(Get-Process -Name Marathon -ErrorAction Stop)
if ($gameProcess.Count -ne 1) { throw 'Expected exactly one Marathon process' }
$runDirectory = Join-Path 'D:\Marathon-preservation\analysis' ('state8-review-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
python .\scripts\capture_state8_evidence.py --pid ($gameProcess[0].Id) --expected-exe 'D:\Marathon-live\Marathon.exe' --output (Join-Path $runDirectory 'title') --label 'title-screen-observed' --lmdetail "$env:LOCALAPPDATA\Temp\Marathon\lmdetail.json"
```

Advance through the title screen yourself. When lmdetail shows state `8`, run:

```powershell
python .\scripts\capture_state8_evidence.py --pid ($gameProcess[0].Id) --expected-exe 'D:\Marathon-live\Marathon.exe' --output (Join-Path $runDirectory 'state8') --label 'state8-observed' --lmdetail "$env:LOCALAPPDATA\Temp\Marathon\lmdetail.json"
$capture = Get-Content -LiteralPath (Join-Path $runDirectory 'state8\capture-manifest.json') -Raw | ConvertFrom-Json
python .\scripts\audit_state8_evidence.py --dump-dir (Join-Path $runDirectory 'state8') --pe 'D:\Marathon-live\Marathon.exe' --image-base $capture.image_base --output (Join-Path $runDirectory 'state8-audit.json')
Write-Output $runDirectory
```

Expected: capture `status: complete`; offline audit completes without digest,
base or size mismatch. A read/access failure is a failed capture, not evidence
of a game defect; keep its manifest. No proxy changes, fabricated tasks, or
state-forcing patches are part of this test.

The new captures answer whether the suspect bytes change between title and
State 8 and supply the five in-image candidate callees. They do not prove the
handoff's mapping merely by existing. The next analysis must establish an actual
dispatcher/caller chain and settings parser before proposing a content schema.
State 9 success requires a fresh, correctly attributed state `9` observation
and its session evidence; server 200s or a test assertion alone do not count.
