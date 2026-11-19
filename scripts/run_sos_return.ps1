[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ArtifactDirectory,
    [ValidateRange(60,300)][int]$Seconds = 180
)
$ErrorActionPreference = 'Stop'
$repo = 'D:\vault-breaker-preservation'
$gameDirectory = 'D:\Marathon-live'
$gameExecutable = Join-Path $gameDirectory 'Marathon.exe'
$liveDll = Join-Path $gameDirectory 'steam_api64.dll'
$artifact = [IO.Path]::GetFullPath($ArtifactDirectory)
if (-not $artifact.StartsWith((Join-Path $repo 'artifacts\'), [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Artifact directory must be inside this repository artifacts directory.'
}
$manifestPath = Join-Path $artifact 'manifest.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$candidate = Join-Path $artifact 'steam_api64.dll'
$baseline = Join-Path $artifact 'baseline\steam_api64.dll'
function Assert-Hash([string]$Path, [string]$Expected) {
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $Expected.ToLowerInvariant()) { throw "Hash mismatch: $Path" }
}
if ($manifest.observer_mode -ne 'sos-work-return-v1') {
    throw 'This launcher requires the sos-work-return-v1 artifact manifest.'
}
Assert-Hash $PSCommandPath $manifest.launcher_sha256
Assert-Hash (Join-Path $repo 'scripts\serve_readonly_capture.py') $manifest.reader_sha256
Assert-Hash (Join-Path $repo 'scripts\capture_http_state.py') $manifest.capture_library_sha256
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this one-test launcher from Administrator PowerShell so capture and cleanup have matching access.'
}
if (@(Get-Process -Name Marathon -ErrorAction SilentlyContinue).Count) {
    throw 'A Marathon process is already running. Close it before the single controlled test.'
}
Assert-Hash $gameExecutable 'd5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd'
Assert-Hash $candidate $manifest.candidate_sha256
Assert-Hash $baseline $manifest.baseline_sha256
Assert-Hash $liveDll $manifest.baseline_sha256
# Read-only verification. This launcher never creates, enables, or changes firewall rules.
$filters = @(Get-NetFirewallApplicationFilter -Program $gameExecutable)
$blockRules = @($filters | Get-NetFirewallRule | Where-Object {
    $_.Enabled -eq 'True' -and $_.Direction -eq 'Outbound' -and $_.Action -eq 'Block' -and $_.Profile -eq 'Any'
})
if (-not $blockRules.Count) { throw 'No enabled outbound block rule covering all profiles was found for the offline executable.' }
if (@(Get-NetFirewallProfile | Where-Object { -not $_.Enabled }).Count) {
    throw 'Firewall profile verification failed. No client was started and no firewall setting was changed.'
}
if (-not @(Get-NetTCPConnection -State Listen -LocalPort 8080 -ErrorAction SilentlyContinue).Count) {
    throw 'The existing local backend must be listening on port 8080 before this test.'
}
# Multiple PATH matches produce an array; Start-Process requires one executable.
[string]$python = (Get-Command python.exe -CommandType Application | Select-Object -First 1).Source
if ([string]::IsNullOrWhiteSpace($python) -or -not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw 'A Python executable could not be resolved. No client was started.'
}
& $python -c 'import ctypes, hashlib, json, sys; assert sys.version_info >= (3, 11)' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Python 3.11 or newer is required. No client was started.' }
$capture = Join-Path 'D:\Marathon-preservation\analysis' ('sos-return-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $capture -ErrorAction Stop | Out-Null
$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $capture 'build-manifest.json') -Encoding UTF8
$blockRules | Select-Object Name,Enabled,Direction,Action,Profile | ConvertTo-Json -Depth 4 |
    Set-Content -LiteralPath (Join-Path $capture 'firewall-before.json') -Encoding UTF8
New-Item -ItemType File -Path (Join-Path $capture 'ARM_SOS_RETURN') -ErrorAction Stop | Out-Null
$oldDirectory = [Environment]::GetEnvironmentVariable('MARATHON_SOS_RETURN_DIR','Process')
New-Item -ItemType File -Path (Join-Path $artifact 'TEST_STARTED') -ErrorAction Stop | Out-Null
$game = $null
$reader = $null
$deployed = $false
$failure = $null
$endReason = 'deadline'
$naturalExitCode = $null
try {
    # Even a failed/partial copy must enter the baseline-restoration path.
    $deployed = $true
    Copy-Item -LiteralPath $candidate -Destination $liveDll -Force
    Assert-Hash $liveDll $manifest.candidate_sha256
    $env:MARATHON_SOS_RETURN_DIR = $capture
    $game = Start-Process -FilePath $gameExecutable -WorkingDirectory $gameDirectory -PassThru -WindowStyle Normal
    $readerDirectory = Join-Path $capture 'reader'
    $reader = Start-Process -FilePath $python -ArgumentList @(
        (Join-Path $repo 'scripts\serve_readonly_capture.py'), '--pid', "$($game.Id)",
        '--expected-exe', $gameExecutable, '--session-dir', $readerDirectory,
        '--allow-data', '--minutes', '5', '--max-mib', '1'
    ) -WorkingDirectory $repo -PassThru -WindowStyle Hidden `
      -RedirectStandardOutput (Join-Path $capture 'reader.stdout.log') `
      -RedirectStandardError (Join-Path $capture 'reader.stderr.log')
    [pscustomobject]@{status='running';pid=$game.Id;capture_dir=$capture;reader_dir=$readerDirectory;
        max_seconds=$Seconds;baseline_sha256=$manifest.baseline_sha256} |
        ConvertTo-Json -Compress | Write-Host
    Write-Host 'Use normal sign-in. Native work is observed without forcing state. Leave this console open for automatic rollback.'
    $endPath = Join-Path $capture ("sos-$($game.Id)-1-return.json")
    $entryPath = Join-Path $capture ("sos-$($game.Id)-1-entry.json")
    $returnSeen = $null
    $nextSample = Get-Date
    $sampleIndex = 0
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        $game.Refresh()
        if ($game.HasExited) { $endReason = 'client_exited'; $naturalExitCode = $game.ExitCode; break }
        if (Test-Path -LiteralPath $endPath) {
            if ($null -eq $returnSeen) {
                $returnSeen = Get-Date
                $returnRecord = Get-Content -LiteralPath $endPath -Raw | ConvertFrom-Json
                @{status='native_return';pid=$game.Id;raw_return=$returnRecord.raw_return_hex;
                    low32=$returnRecord.return_low32;capture_dir=$capture} | ConvertTo-Json -Compress | Write-Host
            }
        }
        # Read task publication even if native work leaves through an exception
        # or other path that does not reach the normal return observation.
        if ((Test-Path -LiteralPath $entryPath) -or $null -ne $returnSeen) {
            $sessionPath = Join-Path $readerDirectory 'session.json'
            if ($sampleIndex -lt 64 -and (Get-Date) -ge $nextSample -and (Test-Path -LiteralPath $sessionPath)) {
                $session = Get-Content -LiteralPath $sessionPath -Raw | ConvertFrom-Json
                $imageBase = [Convert]::ToUInt64($session.image_base.Substring(2),16)
                $ranges = @(
                    @{address=('0x'+($imageBase+0x3683e9a0).ToString('x'));bytes=8},
                    @{address=('0x'+($imageBase+0x367a5f98).ToString('x'));bytes=8},
                    @{address=('0x'+($imageBase+0x367a5fb0).ToString('x'));bytes=8}
                )
                $sampleIndex++
                $requestName = 'request-'+(900000+$sampleIndex).ToString('000000')+'.json'
                $requestPath = Join-Path $readerDirectory $requestName
                @{ranges=$ranges} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath ($requestPath+'.tmp') -Encoding ASCII
                Move-Item -LiteralPath ($requestPath+'.tmp') -Destination $requestPath -ErrorAction Stop
                $nextSample = (Get-Date).AddSeconds(1)
            }
        }
        if ($null -ne $returnSeen -and (Get-Date) -ge $returnSeen.AddSeconds(25)) { $endReason='return_observed'; break }
        if (Test-Path -LiteralPath (Join-Path $capture 'STOP_SOS_RETURN')) { $endReason = 'stop_requested'; break }
        Start-Sleep -Milliseconds 500
    }
} catch {
    $failure = $_.Exception.Message
    $endReason = 'launcher_error'
    Write-Warning $failure
} finally {
    try {
        if ($deployed) {
            try {
                New-Item -ItemType File -Path (Join-Path $capture 'STOP_SOS_RETURN') -Force | Out-Null
                $readerStop = Join-Path $capture 'reader\STOP'
                if (Test-Path -LiteralPath (Split-Path $readerStop)) {
                    New-Item -ItemType File -Path $readerStop -Force | Out-Null
                }
            } catch { Write-Warning "Stop-marker write failed: $($_.Exception.Message)" }
            # Allow pending observation IO before ending the owned test process.
            Start-Sleep -Seconds 2
            try {
                if ($game) {
                    $game.Refresh()
                    if (-not $game.HasExited) {
                        $null = $game.CloseMainWindow()
                        if (-not $game.WaitForExit(5000)) { $game.Kill(); $null = $game.WaitForExit(5000) }
                    }
                }
            } catch { Write-Warning "Owned client cleanup failed: $($_.Exception.Message)" }
            try {
                if ($reader) {
                    $reader.Refresh()
                    if (-not $reader.HasExited -and -not $reader.WaitForExit(3000)) { $reader.Kill() }
                }
            } catch { Write-Warning "Reader cleanup failed: $($_.Exception.Message)" }
            $restored = $false
            try {
                # Never replace an in-use DLL if an unrelated instance appeared.
                if (@(Get-Process -Name Marathon -ErrorAction SilentlyContinue).Count) {
                    throw "A running Marathon process prevents rollback. Baseline backup: $baseline"
                }
                Copy-Item -LiteralPath $baseline -Destination $liveDll -Force
                Assert-Hash $liveDll $manifest.baseline_sha256
                $restored = $true
                Write-Host "Test ended. Original DLL restored. Evidence: $capture"
            } finally {
                # Evidence IO must never prevent the rollback attempt above.
                try {
                    if (Test-Path -LiteralPath (Join-Path $gameDirectory 'marathon_proxy.log')) {
                        Copy-Item -LiteralPath (Join-Path $gameDirectory 'marathon_proxy.log') `
                            -Destination (Join-Path $capture 'marathon_proxy.log')
                    }
                    [pscustomobject]@{status=$(if ($restored) {'restored'} else {'rollback_failed'});
                        capture_dir=$capture;failure=$failure;baseline_backup=$baseline;
                        reason=$endReason;natural_exit_code=$naturalExitCode;
                        client_exit_code=$(if ($game -and $game.HasExited) {$game.ExitCode} else {$null});
                        restored_sha256=$(if ($restored) {$manifest.baseline_sha256} else {$null})} |
                        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $capture 'launcher-ended.json') -Encoding UTF8
                } catch { Write-Warning "Evidence archive failed: $($_.Exception.Message)" }
            }
        }
    } finally {
        if ($null -eq $oldDirectory) { Remove-Item Env:\MARATHON_SOS_RETURN_DIR -ErrorAction SilentlyContinue }
        else { $env:MARATHON_SOS_RETURN_DIR = $oldDirectory }
    }
}
if ($failure) { throw $failure }
