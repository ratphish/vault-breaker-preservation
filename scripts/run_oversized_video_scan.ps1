$ErrorActionPreference='Continue'
$env:MIDA_DIR='C:\Users\marra\Documents\Codex\2026-10-27\hel\work\tools\MIDA';$env:MARATHON_PACKAGES='D:\Marathon-preservation\build-26136895-20261031\packages'
$dotnet='C:\Users\marra\Documents\Codex\2026-10-27\hel\work\tools\dotnet10\dotnet.exe'
$results=Join-Path $PSScriptRoot '..\research\vault-oversized-video-matches.jsonl';$errors=Join-Path $PSScriptRoot '..\research\vault-oversized-video-errors.txt'
if((Test-Path -LiteralPath $results) -or (Test-Path -LiteralPath $errors)){throw 'Output exists'}
$items=Get-Content (Join-Path $PSScriptRoot '..\research\package-oversized-entries.jsonl') | ForEach-Object {$_ | ConvertFrom-Json}
foreach($item in $items){
 & $dotnet run --no-build --project (Join-Path $PSScriptRoot 'script_path_probe') -p:MidaDir=$env:MIDA_DIR -- scan-one-oversized $item.tag 1>>$results 2>>$errors
 if($LASTEXITCODE -ne 0){Write-Output "failed $($item.tag): $LASTEXITCODE"}else{Write-Output "checked $($item.tag)"}
}
