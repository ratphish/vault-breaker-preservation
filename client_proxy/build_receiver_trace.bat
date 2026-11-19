@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 exit /b 1
set "out=%~dp0..\artifacts\receiver-trace"
set "tabletrace="
set "receivertrace=/DMARATHON_NATIVE_RECEIVER_TRACE"
if /i "%~1"=="tables" set "tabletrace=/DMARATHON_NATIVE_TABLE_TRACE"
if /i "%~1"=="writer" set "receivertrace=/DMARATHON_STATE_RECEIVER_TRACE"
if /i "%~1"=="task" set "receivertrace=/DMARATHON_STATE_TASK_WATCH"
if /i "%~1"=="sos" set "receivertrace=/DMARATHON_LOCAL_SOS_ROUTING"
if not exist "%out%" mkdir "%out%"
pushd "%out%"
cl /nologo /O2 /W3 /EHsc /std:c++17 "%~dp0..\tests\test_native_http_receiver.cpp" /Fe:receiver_test.exe /Fo:receiver_test.obj
if errorlevel 1 goto failed
receiver_test.exe
if errorlevel 1 goto failed
if /i not "%~1"=="writer" goto builddll
if not exist writer-tests mkdir writer-tests
cl /nologo /O2 /W3 /EHsc /std:c++17 "%~dp0..\tests\test_state_writer_observation.cpp" /Fe:writer_test.exe /Fo:writer_test.obj
if errorlevel 1 goto failed
writer_test.exe "%out%\writer-tests"
if errorlevel 1 goto failed
:builddll
cl /nologo /LD /O2 /W3 /EHsc /std:c++17 %receivertrace% %tabletrace% "%~dp0steam_api64.cpp" /Fo:proxy_receiver.obj /link /nologo /DEF:"%~dp0steam_api64.def" /OUT:steam_api64.dll /IMPLIB:proxy_receiver.lib ws2_32.lib crypt32.lib winhttp.lib
if errorlevel 1 goto failed
popd
exit /b 0
:failed
popd
exit /b 1
