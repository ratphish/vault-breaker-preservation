# Manual runtime test of the Dawn-derived callback correction

Both game proxy DLLs now contain the tested v2 candidate, SHA-256
`4c708f8e7ea0461650ab1c6c2d5e3a36dea1b03a740918efb8adc8b5943a6b04`.
They were installed only after verifying no Marathon process existed. Source
hashes matched the native-test build manifest. The old files and proxy log are
preserved at:

`D:\Marathon-preservation\backups\proxy-http-v2-20261110-204020-6f34ad4a`

`deployment.json` there records both old hashes, backups and verified targets.
The server was still listening on TCP 80/443/8080/8081/7777, PID 18460. It was
not restarted; its newer peer-PID source addition therefore remains inactive.
The agent did not launch a game, send input or control the desktop.

## User-run procedure

1. Launch Marathon normally yourself and go through sign-in as usual.
2. If it stalls, leave it running for 60 seconds and report that it is stuck.
   If it advances, report which screen/state it reaches; do not assume the
   absence of the old screen proves the full preservation goal.
3. While it is still running, use **Administrator PowerShell** for this
   read-only capture. The command discovers the current process rather than
   reusing an expired PID. Use exactly one running Marathon instance.

```powershell
$marathonTraceProcesses = @(Get-Process -Name Marathon -ErrorAction Stop)
if ($marathonTraceProcesses.Count -ne 1) { throw 'Expected exactly one running Marathon process.' }
$marathonTracePid = $marathonTraceProcesses[0].Id
$marathonTraceOutput = 'D:\Marathon-preservation\analysis\http-completion-' + $marathonTracePid + '-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json'
python D:\vault-breaker-preservation\scripts\capture_http_state.py --pid $marathonTracePid --expected-exe D:\Marathon-live\Marathon.exe --output $marathonTraceOutput --http-code
```

Reply with the printed result. The capture reads the current import bindings,
a pinned 272-KiB code/data set identified from the previous native WinHTTP
caller, and module inventory. It neither suspends nor writes the process.
Its sequential reads are not an execution trace or a call stack. It requires
the pinned executable hash and a new output filename. A failure report should
be preserved, not overwritten.

For the current PID 34652 session, the initial capture has already succeeded
and identified the native callback. The remaining requested handler-page
capture is separate and does not require a new launch:

```powershell
$handlerTracePid = (Get-Process -Name Marathon -ErrorAction Stop).Id
$handlerTraceOutput = 'D:\Marathon-preservation\analysis\http-handlers-' + $handlerTracePid + '-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json'
python D:\vault-breaker-preservation\scripts\capture_http_state.py --pid $handlerTracePid --expected-exe D:\Marathon-live\Marathon.exe --output $handlerTraceOutput --callback-stubs
```

This reads 84 KiB of protected handler pages selected from the bounded offline
model. It authenticates candidate code, not execution of those instructions.

## Evidence the next analysis must check

- New PID/session and fresh lmdetail, not the old PID 2044 session.
- Startup marker `http-bootstrap-observation-v2` and installed hash provenance.
- Encrypted app-ticket call results go through the corrected overload with
  their original 64-bit handle; the native fixture already verifies this ABI.
- No fabricated callback 337 invitation. Persona events use 304; avatar uses
  334 if that synthetic event is emitted.
- WinHTTP request identity, numeric HTTP status queries, read/available-byte
  outputs and registered native callback code identity. Asynchronous returns
  alone do not prove an EOF or engine task completion.
- Fresh code at callback registration/receive/read/status paths, mapped through
  the captured API table. The previous synthetic text is not a substitute for
  current runtime code.
- A native result/pending-state transition and its consumer before claiming
  a State 8 root cause. Dawn's Destiny offsets must not be written into Marathon.

The next run is an experiment, not an assurance of advancement. Current
validation covers 51 Python tests, 80 HTTP observer assertions, 368 transport
assertions and the compiler-generated callback ABI/ID regression. The old
callback/ordinal controls fail as expected; the corrected controls pass.
