[CmdletBinding()]
param()

$python = (Get-Command python.exe -CommandType Application | Select-Object -First 1).Source
if (-not $python) {
    throw "python.exe not found in PATH"
}

& $python (Join-Path $PSScriptRoot "unblock_signing_in.py") @args
exit $LASTEXITCODE
