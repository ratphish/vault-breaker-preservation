param(
  [Parameter(Mandatory=$true)][string]$Snapshot,
  [Parameter(Mandatory=$true)][string]$OutputFile,
  [Parameter(Mandatory=$true)][string]$ReaCmd,
  [Parameter(Mandatory=$true)][string]$GhidraDir,
  [Parameter(Mandatory=$true)][string]$JavaDir
)
$ErrorActionPreference='Stop'
if (Test-Path -LiteralPath $OutputFile) { throw 'Output file already exists.' }
$seed=Join-Path $PSScriptRoot '..\research\ghidra-script-export-seed.txt'
$env:GHIDRA_INSTALL_DIR=$GhidraDir
$env:JAVA_HOME=$JavaDir
$env:REA_GHIDRA_STARTUP_TIMEOUT_MS='600000'
$env:REA_GHIDRA_DISABLED_ANALYZERS='Function Start Search,Subroutine References,Disassemble Entry Points'
$env:REA_GHIDRA_SEED_FILE=(Resolve-Path -LiteralPath $seed).Path
$target=Join-Path $Snapshot 'Marathon.exe'
& $ReaCmd decompile $target --file-offset 0x2f7a1c90 --provider ghidra --format json | Set-Content -LiteralPath $OutputFile -Encoding utf8
exit $LASTEXITCODE
