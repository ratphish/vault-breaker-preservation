@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "%~dp0"
echo [*] Compiling steam_api64_diag.dll for Marathon (x64)...
cl /nologo /LD /O2 /W3 /EHsc /D_USRDLL /D_WINDLL steam_api64_diag.cpp /link /nologo /DEF:steam_api64.def /OUT:steam_api64_diag.dll ws2_32.lib crypt32.lib winhttp.lib bcrypt.lib user32.lib
if %ERRORLEVEL% equ 0 (
    echo [+] Successfully compiled steam_api64_diag.dll!
    copy /Y steam_api64_diag.dll "D:\Marathon-live\steam_api64.dll"
    copy /Y steam_api64_diag.dll "D:\Marathon-live\bin\x64\steam_api64.dll"
    echo [+] Deployed steam_api64_diag.dll to D:\Marathon-live!
) else (
    echo [-] Build failed with error %ERRORLEVEL%
)
endlocal
