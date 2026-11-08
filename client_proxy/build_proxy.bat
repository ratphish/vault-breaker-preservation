@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cd /d "%~dp0"
echo [*] Compiling steam_api64.dll for Marathon (x64)...
cl /nologo /LD /O2 /W3 /EHsc /D_USRDLL /D_WINDLL steam_api64.cpp /link /nologo /DEF:steam_api64.def /OUT:steam_api64.dll ws2_32.lib
if %ERRORLEVEL% equ 0 (
    echo [+] Successfully compiled steam_api64.dll!
) else (
    echo [-] Build failed with error %ERRORLEVEL%
)
endlocal
