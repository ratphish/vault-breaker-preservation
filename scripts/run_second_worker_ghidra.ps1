$ErrorActionPreference='Stop'
$root='D:\Marathon-preservation\ghidra-second-worker'
$inputs='D:\Marathon-preservation\analysis\second-worker-ghidra-inputs'
if(Test-Path -LiteralPath $root){throw 'Output already exists.'}
New-Item -ItemType Directory -Path $root | Out-Null
$env:JAVA_HOME='C:\Users\marra\Documents\Codex\2026-10-27\hel\work\tools\jdk-25.0.5+8'
$headless='C:\Users\marra\Documents\Codex\2026-10-27\hel\work\tools\ghidra_12.1.4_PUBLIC\support\analyzeHeadless.bat'
$items=Get-Content (Join-Path $inputs 'manifest.json') -Raw | ConvertFrom-Json
foreach($item in $items) {
  $out=Join-Path $root ([string]$item.window)
  New-Item -ItemType Directory -Path $out | Out-Null
  foreach($n in @('project','home','tmp','roaming','local')) {New-Item -ItemType Directory -Path (Join-Path $out $n) | Out-Null}
  $env:APPDATA=Join-Path $out 'roaming'
  $env:LOCALAPPDATA=Join-Path $out 'local'
  $env:JDK_JAVA_OPTIONS='-Duser.home="'+(Join-Path $out 'home')+'" -Djava.io.tmpdir="'+(Join-Path $out 'tmp')+'" -XX:-UsePerfData'
  $inputDir=Join-Path $inputs ([string]$item.window)
  & $headless (Join-Path $out 'project') 'second-worker' -import (Join-Path $inputDir 'range.bin') -loader BinaryLoader -loader-baseAddr $item.base -processor x86:LE:64:default -cspec windows -readOnly -deleteProject -noanalysis -scriptPath (Join-Path $PSScriptRoot 'ghidra') -postScript BatchBoundedFunctions.java (Join-Path $inputDir 'ranges.txt') -log (Join-Path $out 'ghidra.log') -scriptlog (Join-Path $out 'script.log') 1> (Join-Path $out 'stdout.txt') 2> (Join-Path $out 'stderr.txt')
  if($LASTEXITCODE -ne 0){throw "Ghidra window $($item.window) failed with $LASTEXITCODE"}
  Write-Output "Window $($item.window) completed."
}
