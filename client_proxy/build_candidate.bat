@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 exit /b 1
set "candidate=%~dp0..\artifacts\bootstrap-fix"
if not exist "%candidate%" mkdir "%candidate%"
if errorlevel 1 exit /b 1
pushd "%candidate%"
cl /nologo /LD /O2 /W3 /EHsc /std:c++17 /D_USRDLL /D_WINDLL /DMARATHON_BOOTFLOW_HOOK "%~dp0steam_api64.cpp" /Fo:proxy_candidate.obj /link /nologo /DEF:"%~dp0steam_api64.def" /OUT:steam_api64.dll /IMPLIB:proxy_candidate.lib ws2_32.lib crypt32.lib winhttp.lib
if errorlevel 1 goto failed
cl /nologo /O2 /W3 /EHsc /std:c++17 "%~dp0..\tests\test_proxy_transport.cpp" /Fo:transport_test.obj /Fe:transport_test.exe /link /nologo ws2_32.lib crypt32.lib winhttp.lib
if errorlevel 1 goto failed
cl /nologo /O2 /W3 /EHsc /std:c++17 /DMARATHON_TEST_BASELINE "%~dp0..\tests\test_proxy_transport.cpp" /Fo:transport_baseline_test.obj /Fe:transport_baseline_test.exe /link /nologo ws2_32.lib crypt32.lib winhttp.lib
if errorlevel 1 goto failed
echo Checking the old baseline fails the HTTP-routing regression, as expected:
transport_baseline_test.exe
if not "%ERRORLEVEL%" == "1" goto failed
echo Checking the candidate fixes the regression:
transport_test.exe
if errorlevel 1 goto failed
popd
echo Candidate and tests are in %candidate%. No files were deployed.
exit /b 0
:failed
popd
exit /b 1
