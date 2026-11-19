[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$repo = 'D:\vault-breaker-preservation'
$expectedExe = 'D:\Marathon-live\Marathon.exe'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run from Administrator PowerShell.'
}
$games = @(Get-CimInstance Win32_Process -Filter "Name='Marathon.exe'" | Where-Object {
    $_.ExecutablePath -eq $expectedExe
})
if ($games.Count -ne 1) { throw 'Expected exactly one running preserved Marathon client. Launch it normally and reach the Signing in stall first.' }
$rules = @(Get-NetFirewallApplicationFilter -Program $expectedExe | Get-NetFirewallRule | Where-Object {
    $_.Enabled -eq 'True' -and $_.Direction -eq 'Outbound' -and $_.Action -eq 'Block' -and $_.Profile -eq 'Any'
})
if (-not $rules.Count -or @(Get-NetFirewallProfile | Where-Object {-not $_.Enabled}).Count) {
    throw 'The existing outbound block and firewall profiles must stay enabled. No firewall settings were changed.'
}
[string]$python = (Get-Command python.exe -CommandType Application | Select-Object -First 1).Source
$capture = Join-Path 'D:\Marathon-preservation\analysis' ('signon-errors-'+(Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $capture -ErrorAction Stop | Out-Null
$sessionDir = Join-Path $capture 'reader'
$reader = $null
function Read-Hex([string]$Value) {
    if ($Value.Length % 2) { throw 'Invalid byte string returned by reader.' }
    [byte[]]$bytes = New-Object byte[] ($Value.Length/2)
    for ($i=0; $i -lt $bytes.Length; $i++) { $bytes[$i]=[Convert]::ToByte($Value.Substring($i*2,2),16) }
    return ,$bytes
}
try {
    $reader = Start-Process -FilePath $python -ArgumentList @(
        (Join-Path $repo 'scripts\serve_readonly_capture.py'),'--pid',"$($games[0].ProcessId)",
        '--expected-exe',$expectedExe,'--session-dir',$sessionDir,'--minutes','1','--max-mib','1'
    ) -WorkingDirectory $repo -WindowStyle Hidden -PassThru `
      -RedirectStandardOutput (Join-Path $capture 'reader.stdout.log') `
      -RedirectStandardError (Join-Path $capture 'reader.stderr.log')
    $sessionPath = Join-Path $sessionDir 'session.json'
    $deadline = (Get-Date).AddSeconds(12)
    while (-not (Test-Path -LiteralPath $sessionPath)) {
        $reader.Refresh()
        if ($reader.HasExited -or (Get-Date) -ge $deadline) { throw "Reader startup failed. Inspect $capture\reader.stderr.log" }
        Start-Sleep -Milliseconds 200
    }
    $session = Get-Content -LiteralPath $sessionPath -Raw | ConvertFrom-Json
    $imageBase = [Convert]::ToUInt64($session.image_base.Substring(2),16)
    # All reads are inside the pinned executable image. No heap access needed.
    # Retained region = status mask + 64 entitlement DWORDs + count (264 bytes).
    # Original error-list interpretation was disproven by the captured IDs.
    $ranges = @()
    foreach ($row in @(@(0x367a2018,4),@(0x367a21d0,4),@(0x367a2350,264),@(0x3683e9a0,8),@(0x367a5f98,8),@(0x367a5fb0,8))) {
        $ranges += @{address=('0x'+($imageBase+[long]$row[0]).ToString('x'));bytes=[int]$row[1]}
    }
    $requestPath = Join-Path $sessionDir 'request-000001.json'
    @{ranges=$ranges;requested_utc=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath ($requestPath+'.tmp') -Encoding ASCII
    Move-Item -LiteralPath ($requestPath+'.tmp') -Destination $requestPath
    $resultPath = Join-Path $sessionDir 'result-000001.json'
    $deadline = (Get-Date).AddSeconds(12)
    while (-not (Test-Path -LiteralPath $resultPath)) {
        $reader.Refresh()
        if ($reader.HasExited -or (Get-Date) -ge $deadline) { throw "Reader did not finish the single request. Evidence: $capture" }
        Start-Sleep -Milliseconds 200
    }
    # The existing reader writes its JSON directly. Wait for a complete document.
    $result = $null
    while ($null -eq $result -and (Get-Date) -lt $deadline) {
        try { $result = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json -ErrorAction Stop }
        catch { Start-Sleep -Milliseconds 100 }
    }
    if ($null -eq $result -or $result.status -ne 'complete') { throw "Incomplete read. Preserve $resultPath" }
    $eventBytes = Read-Hex $result.ranges[0].hex
    $stateBytes = Read-Hex $result.ranges[1].hex
    $errorBytes = Read-Hex $result.ranges[2].hex
    $taskBytes = Read-Hex $result.ranges[3].hex
    $httpBytes = Read-Hex $result.ranges[4].hex
    $receivedBytes = Read-Hex $result.ranges[5].hex
    $count = [BitConverter]::ToUInt32($errorBytes,260)
    if ($count -gt 64) { throw "List count $count exceeds the recovered 64-entry bound; raw data retained, no further reads." }
    $operationState = [BitConverter]::ToUInt32($stateBytes,0)
    $codes = @()
    if ($operationState -eq 3) {
        for ($i=0; $i -lt $count; $i++) { $codes += ('0x'+[BitConverter]::ToUInt32($errorBytes,4+$i*4).ToString('x8')) }
    }
    $summary = [ordered]@{
        status='complete';pid=$games[0].ProcessId;capture_dir=$capture;captured_utc=[DateTime]::UtcNow.ToString('o');
        event_kind=[BitConverter]::ToUInt32($eventBytes,0);operation_state=$operationState;
        status_mask_raw=('0x'+[BitConverter]::ToUInt32($errorBytes,0).ToString('x8'));
        entitlement_count_raw=$count;entitlement_ids_hex=$codes;entitlement_list_interpreted=($operationState -eq 3);
        task_state=[BitConverter]::ToUInt32($taskBytes,0);task_result=[BitConverter]::ToUInt32($taskBytes,4);
        http_state=[BitConverter]::ToUInt32($httpBytes,0);http_status=[BitConverter]::ToUInt32($httpBytes,4);
        received_bytes=[BitConverter]::ToUInt64($receivedBytes,0);
        limitation='One sequential read-only snapshot; no execution history. State3 is not proof of rejection. Entitlement identity established from backend field10 and captured values.'
    }
    $summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $capture 'error-summary.json') -Encoding UTF8
    $summary | ConvertTo-Json -Depth 5
} finally {
    if (Test-Path -LiteralPath $sessionDir) { New-Item -ItemType File -Path (Join-Path $sessionDir 'STOP') -Force | Out-Null }
    if ($reader) {
        try { if (-not $reader.WaitForExit(5000)) { $reader.Kill(); $null=$reader.WaitForExit(5000) } }
        catch { Write-Warning "Reader cleanup: $($_.Exception.Message)" }
    }
    Write-Host "Evidence directory: $capture"
}
