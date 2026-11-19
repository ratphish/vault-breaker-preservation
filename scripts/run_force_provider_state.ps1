[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$ArtifactDirectory)
$ErrorActionPreference = 'Stop'
$repo = 'D:\vault-breaker-preservation'
$gameDirectory = 'D:\Marathon-live'
$gameExecutable = Join-Path $gameDirectory 'Marathon.exe'
$liveDll = Join-Path $gameDirectory 'steam_api64.dll'
$artifact = [IO.Path]::GetFullPath($ArtifactDirectory)
if (-not $artifact.StartsWith((Join-Path $repo 'artifacts\'),[StringComparison]::OrdinalIgnoreCase)) {
    throw 'Artifact directory must be inside repository artifacts.'
}
$manifest = Get-Content -LiteralPath (Join-Path $artifact 'manifest.json') -Raw | ConvertFrom-Json
function Assert-Hash([string]$Path,[string]$Expected) {
    if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Expected.ToLowerInvariant()) {
        throw "Hash mismatch: $Path"
    }
}
if ($manifest.mode -ne 'force-state2-v1') { throw 'Wrong one-test manifest.' }
Assert-Hash $PSCommandPath $manifest.launcher_sha256
Assert-Hash (Join-Path $repo 'scripts\force_provider_state_once.py') $manifest.helper_sha256
Assert-Hash (Join-Path $repo 'scripts\capture_http_state.py') $manifest.reader_sha256
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this test from Administrator PowerShell.' }
if (@(Get-Process -Name Marathon -ErrorAction SilentlyContinue).Count) { throw 'Close Marathon before this single fresh-start test.' }
Assert-Hash $gameExecutable $manifest.executable_sha256
Assert-Hash $liveDll $manifest.baseline_sha256
Assert-Hash (Join-Path $artifact 'baseline\steam_api64.dll') $manifest.baseline_sha256
$blockRules = @(Get-NetFirewallApplicationFilter -Program $gameExecutable | Get-NetFirewallRule | Where-Object {
    $_.Enabled -eq 'True' -and $_.Direction -eq 'Outbound' -and $_.Action -eq 'Block' -and $_.Profile -eq 'Any'
})
if (-not $blockRules.Count -or @(Get-NetFirewallProfile | Where-Object {-not $_.Enabled}).Count) {
    throw 'Existing all-profile outbound firewall block must be enabled. No firewall settings were changed.'
}
if (-not @(Get-NetTCPConnection -State Listen -LocalPort 8080 -ErrorAction SilentlyContinue).Count) {
    throw 'Existing local backend must be listening on port8080.'
}
[string]$python = (Get-Command python.exe -CommandType Application | Select-Object -First 1).Source
& $python (Join-Path $repo 'scripts\force_provider_state_once.py') --preflight | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Python3.11/Unicorn preflight failed; no client started.' }
if (Test-Path Env:\MARATHON_PROVIDER_WATCH_DIR) { throw 'Remove the old watcher environment variable before this baseline-only test.' }
$capture = Join-Path 'D:\Marathon-preservation\analysis' ('force-state2-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $capture -ErrorAction Stop | Out-Null
$manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $capture 'manifest.json') -Encoding UTF8
$blockRules | Select-Object Name,Enabled,Direction,Action,Profile | ConvertTo-Json |
    Set-Content -LiteralPath (Join-Path $capture 'firewall-before.json') -Encoding UTF8
# An exclusive claim prevents a second launch with this artifact. No retries.
New-Item -ItemType File -Path (Join-Path $artifact 'TEST_STARTED') -ErrorAction Stop | Out-Null
$game = $null
$failure = $null
$helperExit = $null
$naturalExit = $null
try {
    $game = Start-Process -FilePath $gameExecutable -WorkingDirectory $gameDirectory -PassThru -WindowStyle Normal
    @{mode='force-state2-v1';pid=$game.Id} | ConvertTo-Json |
        Set-Content -LiteralPath (Join-Path $capture 'ARM_FORCE_STATE2.json') -Encoding UTF8
    @{status='running';pid=$game.Id;capture_dir=$capture;mode='one_four_byte_write_after_stable_stall'} |
        ConvertTo-Json -Compress | Write-Host
    Write-Host 'Use normal sign-in. Leave this console open. After the one write, observe the UI for20seconds; this launcher then closes its client.'
    Start-Sleep -Seconds 2
    & $python (Join-Path $repo 'scripts\force_provider_state_once.py') --pid $game.Id --evidence-dir $capture
    $helperExit = $LASTEXITCODE
    if ($helperExit -ne 0) { $failure = 'Helper aborted; inspect helper-ended.json. No automatic retry.' }
} catch {
    $failure = $_.Exception.Message
    Write-Warning $failure
} finally {
    try {
        if ($game) {
            $game.Refresh()
            if ($game.HasExited) { $naturalExit = $game.ExitCode }
            else {
                $null = $game.CloseMainWindow()
                if (-not $game.WaitForExit(5000)) { $game.Kill(); $null = $game.WaitForExit(5000) }
            }
        }
    } finally {
        # No reverse state write: discard this process, including all forced RAM.
        $running = if ($game) { $game.Refresh(); -not $game.HasExited } else { $false }
        $dllVerified = $false
        try { Assert-Hash $liveDll $manifest.baseline_sha256; $dllVerified = $true }
        finally {
            try {
                if (Test-Path -LiteralPath (Join-Path $gameDirectory 'marathon_proxy.log')) {
                    Copy-Item -LiteralPath (Join-Path $gameDirectory 'marathon_proxy.log') -Destination (Join-Path $capture 'marathon_proxy.log')
                }
            } catch { Write-Warning "Proxy-log archive failed: $($_.Exception.Message)" }
            @{status=$(if (-not $running -and $dllVerified) {'rolled_back'} else {'cleanup_incomplete'});
                capture_dir=$capture;client_closed=(-not $running);baseline_dll_verified=$dllVerified;
                dll_replaced=$false;helper_exit=$helperExit;natural_exit=$naturalExit;failure=$failure;
                rollback='Owned process ended; temporary forced state discarded';baseline_backup=(Join-Path $artifact 'baseline\steam_api64.dll')} |
                ConvertTo-Json | Set-Content -LiteralPath (Join-Path $capture 'launcher-ended.json') -Encoding UTF8
            if ($running) {
                Write-Warning "Cleanup incomplete: the test client is still running. Evidence: $capture"
            } else {
                Write-Host "Test ended. Temporary state discarded; baseline DLL verified=$dllVerified. Evidence: $capture"
            }
        }
    }
}
if ($failure) { throw $failure }
