$ErrorActionPreference='Continue'
$out='D:\Marathon-preservation\ghidra-synthetic-largest-batch'
if(Test-Path -LiteralPath $out){throw 'Output already exists'}
New-Item -ItemType Directory -Path $out | Out-Null
foreach($n in @('project','home','tmp','roaming','local')) {New-Item -ItemType Directory -Path (Join-Path $out $n) | Out-Null}
$env:APPDATA=Join-Path $out 'roaming'; $env:LOCALAPPDATA=Join-Path $out 'local'
$env:JAVA_HOME='C:\Users\marra\Documents\Codex\2026-10-27\hel\work\tools\jdk-25.0.5+8'
$env:JDK_JAVA_OPTIONS='-Duser.home="'+(Join-Path $out 'home')+'" -Djava.io.tmpdir="'+(Join-Path $out 'tmp')+'" -XX:-UsePerfData'
$headless='C:\Users\marra\Documents\Codex\2026-10-27\hel\work\tools\ghidra_12.1.4_PUBLIC\support\analyzeHeadless.bat'
& $headless (Join-Path $out 'project') 'synthetic-largest' -import 'D:\Marathon-preservation\analysis\largest-synthetic-range-63675\synthetic-range.bin' -loader BinaryLoader -loader-baseAddr 0x16ee4036d -processor x86:LE:64:default -cspec windows -readOnly -deleteProject -noanalysis -scriptPath (Join-Path $PSScriptRoot 'ghidra') -postScript BatchBoundedFunctions.java 'D:\Marathon-preservation\analysis\largest-text-pdata-ranges.txt' -log (Join-Path $out 'ghidra.log') -scriptlog (Join-Path $out 'script.log') 1> (Join-Path $out 'stdout.txt') 2> (Join-Path $out 'stderr.txt')
exit $LASTEXITCODE
