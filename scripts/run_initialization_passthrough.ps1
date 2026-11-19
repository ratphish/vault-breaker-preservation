[CmdletBinding()]
param(
    [string]$ArtifactDirectory = 'D:\vault-breaker-preservation\artifacts\local-sos-passthrough-20261113',
    [ValidateRange(60,300)][int]$Seconds = 240
)
$ErrorActionPreference = 'Stop'
$repo = 'D:\vault-breaker-preservation'
$gameDirectory = 'D:\Marathon-live'
$executable = Join-Path $gameDirectory 'Marathon.exe'
$liveDll = Join-Path $gameDirectory 'steam_api64.dll'
$artifact = [IO.Path]::GetFullPath($ArtifactDirectory)
if (-not $artifact.StartsWith($repo+'\artifacts\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Artifact must be inside repository artifacts.' }
$manifest = Get-Content -LiteralPath (Join-Path $artifact 'manifest.json') -Raw | ConvertFrom-Json
function Assert-Hash([string]$Path,[string]$Expected) {
    if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Expected.ToLowerInvariant()) { throw "Hash mismatch: $Path" }
}
function Check-Firewall {
    $rules = @(Get-NetFirewallApplicationFilter -Program $executable | Get-NetFirewallRule | Where-Object {
        $_.Enabled -eq 'True' -and $_.Direction -eq 'Outbound' -and $_.Action -eq 'Block' -and $_.Profile -eq 'Any'
    })
    if (-not $rules.Count -or @(Get-NetFirewallProfile | Where-Object {-not $_.Enabled}).Count) { throw 'Existing all-profile outbound block and firewall profiles must remain enabled.' }
    return $rules
}
function Copy-AppendedLog([string]$Source,[long]$Offset,[string]$Destination) {
    if (-not (Test-Path -LiteralPath $Source)) { return }
    $inputStream = [IO.File]::Open($Source,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
    try {
        if ($Offset -gt $inputStream.Length) { $Offset = 0 }
        $inputStream.Position = $Offset
        $outputStream = [IO.File]::Open($Destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        try { $inputStream.CopyTo($outputStream) } finally { $outputStream.Dispose() }
    } finally { $inputStream.Dispose() }
}
if ($manifest.mode -ne 'native-initialization-passthrough') { throw 'Wrong candidate manifest.' }
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run from Administrator PowerShell.' }
if (@(Get-Process -Name Marathon -ErrorAction SilentlyContinue).Count) { throw 'Close Marathon first.' }
foreach ($name in @('MARATHON_PROVIDER_WATCH_DIR','MARATHON_SOS_RETURN_DIR','MARATHON_RECEIVER_CAPTURE_DIR')) {
    if ([Environment]::GetEnvironmentVariable($name)) { throw "Unexpected observer environment variable: $name" }
}
Assert-Hash $executable 'd5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd'
Assert-Hash $liveDll $manifest.baseline_sha256
$candidate = Join-Path $artifact 'steam_api64.dll'
Assert-Hash $candidate $manifest.candidate_sha256
foreach ($item in $manifest.source_sha256.PSObject.Properties) { Assert-Hash (Join-Path $repo $item.Name) $item.Value }
Assert-Hash $PSCommandPath $manifest.launcher_sha256
Assert-Hash (Join-Path $repo 'scripts\serve_readonly_capture.py') $manifest.reader_sha256
Assert-Hash (Join-Path $repo 'scripts\capture_http_state.py') $manifest.capture_library_sha256
$rules = @(Check-Firewall)
if (-not @(Get-NetTCPConnection -State Listen -LocalPort 8080 -ErrorAction SilentlyContinue).Count) { throw 'Local backend must be listening on port 8080.' }
[string]$python = (Get-Command python.exe -CommandType Application | Select-Object -First 1).Source
$capture = Join-Path 'D:\Marathon-preservation\analysis' ('initialization-passthrough-'+(Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $capture -ErrorAction Stop | Out-Null
$backup = Join-Path $capture 'steam_api64.original.dll'
Copy-Item -LiteralPath $liveDll -Destination $backup
Assert-Hash $backup $manifest.baseline_sha256
$manifest | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $capture 'manifest.json') -Encoding UTF8
$rules | Select-Object Name,Enabled,Direction,Action,Profile | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $capture 'firewall-before.json') -Encoding UTF8
$proxyLog = Join-Path $gameDirectory 'marathon_proxy.log'
$proxyOffset = if (Test-Path -LiteralPath $proxyLog) { (Get-Item -LiteralPath $proxyLog).Length } else { 0 }
$backendLog = 'D:\Marathon-preservation\analysis\backend-settings-replay-20261113-184653\backend.stdout.log'
$backendOffset = if (Test-Path -LiteralPath $backendLog) { (Get-Item -LiteralPath $backendLog).Length } else { 0 }
# Exclusive one-run claim. A failed preflight never consumes it.
New-Item -ItemType File -Path (Join-Path $artifact 'PASSTHROUGH_TEST_STARTED') -ErrorAction Stop | Out-Null
$game = $null; $reader = $null; $failure = $null; $restored = $false; $reason = 'not_started'; $naturalExit = $null
$readerDirectory = Join-Path $capture 'reader'
try {
    Copy-Item -LiteralPath $candidate -Destination $liveDll
    Assert-Hash $liveDll $manifest.candidate_sha256
    $game = Start-Process -FilePath $executable -WorkingDirectory $gameDirectory -WindowStyle Normal -PassThru
    $reader = Start-Process -FilePath $python -ArgumentList @(
        (Join-Path $repo 'scripts\serve_readonly_capture.py'),'--pid',"$($game.Id)",
        '--expected-exe',$executable,'--session-dir',$readerDirectory,'--minutes','5','--max-mib','1'
    ) -WorkingDirectory $repo -WindowStyle Hidden -PassThru `
      -RedirectStandardOutput (Join-Path $capture 'reader.stdout.log') -RedirectStandardError (Join-Path $capture 'reader.stderr.log')
    $sessionPath = Join-Path $readerDirectory 'session.json'
    $readyDeadline = (Get-Date).AddSeconds(12)
    while (-not (Test-Path -LiteralPath $sessionPath)) {
        $reader.Refresh(); $game.Refresh()
        if ($reader.HasExited -or $game.HasExited -or (Get-Date) -ge $readyDeadline) { throw 'Read-only reader did not become ready. No retry; inspect reader logs.' }
        Start-Sleep -Milliseconds 250
    }
    $session = Get-Content -LiteralPath $sessionPath -Raw | ConvertFrom-Json
    $imageBase = [Convert]::ToUInt64($session.image_base.Substring(2),16)
    @{status='capture_ready';pid=$game.Id;capture_dir=$capture;max_seconds=$Seconds;mode='initialization_passthrough_no_state_writes'} | ConvertTo-Json -Compress | Write-Host
    Write-Host 'Use normal sign-in now. At an error or after 30 seconds stuck on Signing in, close Marathon normally. Leave this console open for DLL rollback. The 240-second default deadline also closes this test client.'
    $deadline = (Get-Date).AddSeconds($Seconds); $index = 0; $reason = 'time_limit'
    while ((Get-Date) -lt $deadline) {
        $game.Refresh(); $reader.Refresh()
        if ($game.HasExited) { $reason='client_exited'; $naturalExit=$game.ExitCode; break }
        if ($reader.HasExited) { throw 'Read-only reader exited before the client.' }
        $ranges = @()
        foreach ($row in @(@(0x3658d650,24),@(0x3683e9a0,8),@(0x367a5f98,8),@(0x367a5fb0,8),@(0x367a200c,8),@(0x367a21d0,4),@(0x367a2228,4))) {
            $ranges += @{address=('0x'+($imageBase+[long]$row[0]).ToString('x'));bytes=[int]$row[1]}
        }
        if ($index % 30 -eq 0) {
            foreach ($page in @(0x2fb02000,0x2f52c000,0x309ed000)) { $ranges += @{address=('0x'+($imageBase+$page).ToString('x'));bytes=4096} }
        }
        $index++
        $requestPath = Join-Path $readerDirectory ('request-'+$index.ToString('000000')+'.json')
        @{ranges=$ranges;sample_utc=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath ($requestPath+'.tmp') -Encoding ASCII
        Move-Item -LiteralPath ($requestPath+'.tmp') -Destination $requestPath
        if (Test-Path -LiteralPath (Join-Path $capture 'STOP')) { $reason='stop_requested'; break }
        Start-Sleep -Seconds 1
    }
} catch {
    $failure=$_.Exception.Message; $reason='failed'; Write-Warning $failure
} finally {
    try {
        if ($game) {
            $game.Refresh()
            if (-not $game.HasExited) {
                $null=$game.CloseMainWindow()
                if (-not $game.WaitForExit(5000)) { $game.Kill(); $null=$game.WaitForExit(5000) }
            }
        }
    } catch { $failure="Client cleanup: $($_.Exception.Message)" }
    try {
        if (Test-Path -LiteralPath $readerDirectory) { New-Item -ItemType File -Path (Join-Path $readerDirectory 'STOP') -Force | Out-Null }
        if ($reader -and -not $reader.WaitForExit(5000)) { $reader.Kill(); $null=$reader.WaitForExit(5000) }
    } catch { Write-Warning "Reader cleanup: $($_.Exception.Message)" }
    try {
        if ($game) { $game.Refresh(); if (-not $game.HasExited) { throw 'Owned test client is still running.' } }
        Assert-Hash $backup $manifest.baseline_sha256
        Copy-Item -LiteralPath $backup -Destination $liveDll
        Assert-Hash $liveDll $manifest.baseline_sha256
        $restored=$true
    } catch { $failure="DLL rollback: $($_.Exception.Message)" }
    try {
        Copy-AppendedLog $proxyLog $proxyOffset (Join-Path $capture 'marathon_proxy.test.log')
        Copy-AppendedLog $backendLog $backendOffset (Join-Path $capture 'backend.test.log')
        @(Check-Firewall) | Select-Object Name,Enabled,Direction,Action,Profile | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $capture 'firewall-after.json') -Encoding UTF8
    } catch { Write-Warning "Evidence or firewall verification: $($_.Exception.Message)"; $failure=$_.Exception.Message }
    @{status=$(if ($restored -and -not $failure) {'restored'} else {'cleanup_or_test_failure'});reason=$reason;failure=$failure;natural_exit=$naturalExit;
      baseline_restored=$restored;baseline_sha256=$manifest.baseline_sha256;capture_dir=$capture;pid=$(if ($game) {$game.Id} else {$null});
      scope='One candidate run; read-only sampling, no forced state and no debugger. Sampling is not execution history.'} |
      ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $capture 'launcher-ended.json') -Encoding UTF8
    Write-Host "Test ended. Original DLL restored=$restored. Evidence: $capture"
}
if ($failure) { throw $failure }
