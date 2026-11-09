@echo off
setlocal
cd /d "%~dp0"
echo [*] Restoring baseline steam_api64.dll (SHA-256: 14D835863464502839D9E624B9E2A26F85130508F3B0066BF859A54A8CF213C8)...
copy /Y steam_api64_baseline_14D83586.dll steam_api64.dll
copy /Y steam_api64_baseline_14D83586.dll "D:\Marathon-live\steam_api64.dll"
copy /Y steam_api64_baseline_14D83586.dll "D:\Marathon-live\bin\x64\steam_api64.dll"
echo [+] Baseline successfully restored!
endlocal
