param(
 [Parameter(Mandatory=$true)][string]$Snapshot,
 [Parameter(Mandatory=$true)][string]$OutputDir,
 [Parameter(Mandatory=$true)][string]$GhidraDir,
 [Parameter(Mandatory=$true)][string]$JavaDir
)
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath $OutputDir){throw 'Output directory already exists.'}
New-Item -ItemType Directory -Path $OutputDir | Out-Null
foreach($name in @('project','home','tmp','roaming','local')) {New-Item -ItemType Directory -Path (Join-Path $OutputDir $name) | Out-Null}
$env:APPDATA=Join-Path $OutputDir 'roaming'
$env:LOCALAPPDATA=Join-Path $OutputDir 'local'
$env:JAVA_HOME=$JavaDir
$env:JDK_JAVA_OPTIONS='-Duser.home="'+(Join-Path $OutputDir 'home')+'" -Djava.io.tmpdir="'+(Join-Path $OutputDir 'tmp')+'" -XX:-UsePerfData'
$scriptDir=(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot 'ghidra')).Path
$exe=Join-Path $Snapshot 'Marathon.exe'
$headless=Join-Path $GhidraDir 'support\analyzeHeadless.bat'
& $headless (Join-Path $OutputDir 'project') 'entry-slice' -import $exe -readOnly -deleteProject -noanalysis -scriptPath $scriptDir -postScript EntrySlice.java -log (Join-Path $OutputDir 'ghidra.log') -scriptlog (Join-Path $OutputDir 'script.log') 1> (Join-Path $OutputDir 'stdout.txt') 2> (Join-Path $OutputDir 'stderr.txt')
exit $LASTEXITCODE
