@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 exit /b 1
set "traceout=%~dp0..\artifacts\http-trace"
if not "%~1"=="" set "traceout=%~f1"
if not exist "%traceout%" mkdir "%traceout%"
if errorlevel 1 exit /b 1
pushd "%traceout%"
cl /nologo /LD /O2 /W3 /EHsc /std:c++17 "%~dp0steam_api64.cpp" /Fo:proxy_trace.obj /link /nologo /DEF:"%~dp0steam_api64.def" /OUT:steam_api64.dll /IMPLIB:proxy_trace.lib ws2_32.lib crypt32.lib winhttp.lib
if errorlevel 1 goto failed
cl /nologo /O2 /W3 /EHsc /std:c++17 "%~dp0..\tests\test_http_observation.cpp" /Fo:http_observation_test.obj /Fe:http_observation_test.exe /link /nologo ws2_32.lib crypt32.lib winhttp.lib
if errorlevel 1 goto failed
http_observation_test.exe
if errorlevel 1 goto failed
cl /nologo /O2 /W3 /EHsc /std:c++17 "%~dp0..\tests\test_steam_callback_abi.cpp" /Fo:callback_abi.obj /Fe:callback_abi.exe /link /nologo ws2_32.lib crypt32.lib winhttp.lib
if errorlevel 1 goto failed
callback_abi.exe
if errorlevel 1 goto failed
cl /nologo /O2 /W3 /EHsc /std:c++17 /DMARATHON_TEST_BASELINE "%~dp0..\tests\test_steam_callback_abi.cpp" /Fo:callback_baseline.obj /Fe:callback_baseline.exe /link /nologo ws2_32.lib crypt32.lib winhttp.lib
if errorlevel 1 goto failed
echo Checking the old baseline reproduces the Steam callback ABI defect:
callback_baseline.exe
if not "%ERRORLEVEL%" == "1" goto failed
cl /nologo /O2 /W3 /EHsc /std:c++17 /DMARATHON_TEST_BASELINE "%~dp0..\tests\test_socket_ordinal_regression.cpp" /Fo:ordinal_baseline.obj /Fe:ordinal_baseline.exe /link /nologo ws2_32.lib crypt32.lib winhttp.lib
if errorlevel 1 goto failed
echo Checking the old baseline reproduces the recvfrom ordinal defect:
ordinal_baseline.exe
if not "%ERRORLEVEL%" == "1" goto failed
cl /nologo /O2 /W3 /EHsc /std:c++17 "%~dp0..\tests\test_socket_ordinal_regression.cpp" /Fo:ordinal_fixed.obj /Fe:ordinal_fixed.exe /link /nologo ws2_32.lib crypt32.lib winhttp.lib
if errorlevel 1 goto failed
ordinal_fixed.exe
if errorlevel 1 goto failed
cl /nologo /O2 /W3 /EHsc /std:c++17 "%~dp0..\tests\test_proxy_transport.cpp" /Fo:transport_test.obj /Fe:transport_test.exe /link /nologo ws2_32.lib crypt32.lib winhttp.lib
if errorlevel 1 goto failed
transport_test.exe
if errorlevel 1 goto failed
popd
echo HTTP observation candidate built in %traceout%. Nothing deployed or launched.
exit /b 0
:failed
popd
exit /b 1
