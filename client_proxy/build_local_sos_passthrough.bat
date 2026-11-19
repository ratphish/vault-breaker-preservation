@echo off
setlocal
if "%~1"=="" exit /b 2
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 exit /b 1
set "out=%~f1"
if not exist "%out%" mkdir "%out%"
pushd "%out%"
cl /nologo /O2 /W4 /EHsc /std:c++17 "%~dp0..\tests\test_local_sos_initialization.cpp" /Fe:initialization_test.exe /Fo:initialization_test.obj
if errorlevel 1 goto failed
initialization_test.exe
if errorlevel 1 goto failed
cl /nologo /LD /O2 /W3 /EHsc /std:c++17 /DMARATHON_LOCAL_SOS_ROUTING "%~dp0steam_api64.cpp" /Fo:passthrough.obj /link /nologo /DEF:"%~dp0steam_api64.def" /OUT:steam_api64.dll /IMPLIB:passthrough.lib ws2_32.lib crypt32.lib winhttp.lib
if errorlevel 1 goto failed
popd
echo Isolated initialization-passthrough candidate built. Nothing deployed.
exit /b 0
:failed
popd
exit /b 1
