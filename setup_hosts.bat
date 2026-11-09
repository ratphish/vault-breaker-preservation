@echo off
:: Batch file to redirect Marathon preservation domains to 127.0.0.1
net session >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [!] Requesting Administrator privileges to update hosts file...
    powershell -Command "Start-Process cmd -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

set HOSTS=%SystemRoot%\System32\drivers\etc\hosts
echo [*] Backing up hosts file to %HOSTS%.bak...
copy /Y "%HOSTS%" "%HOSTS%.bak" >nul

echo [*] Updating Marathon preservation domains in hosts file...

:: Clean up old entries first using PowerShell
powershell -Command "$content = (Get-Content -Path '%HOSTS%') -join \"`n\"; $pattern = '(?ms)# Marathon Preservation Local Redirections.*?(?=(?:# (?!Marathon)|$))'; $cleaned = [System.Text.RegularExpressions.Regex]::Replace($content, $pattern, '').TrimEnd(); [System.IO.File]::WriteAllText('%HOSTS%', $cleaned + \"`r`n\")"

(
echo.
echo # Marathon Preservation Local Redirections
echo 127.0.0.1 signon.goliath.prod.gravityshavings.net
echo 127.0.0.1 signon.goliath.prod.deadorbit.net
echo 127.0.0.1 www1.signon.goliath.prod.gravityshavings.net
echo 127.0.0.1 www2.signon.goliath.prod.gravityshavings.net
echo 127.0.0.1 www3.signon.goliath.prod.gravityshavings.net
echo 127.0.0.1 www4.signon.goliath.prod.gravityshavings.net
echo 127.0.0.1 www.signon.goliath.prod.gravityshavings.net
echo 127.0.0.1 www1.signon.goliath.prod.deadorbit.net
echo 127.0.0.1 www2.signon.goliath.prod.deadorbit.net
echo 127.0.0.1 www3.signon.goliath.prod.deadorbit.net
echo 127.0.0.1 www4.signon.goliath.prod.deadorbit.net
echo 127.0.0.1 www.signon.goliath.prod.deadorbit.net
echo 127.0.0.1 client.signon.goliath.prod.deadorbit.net
echo 127.0.0.1 client.signon.goliath.prod.gravityshavings.net
echo 127.0.0.1 auth.signon.goliath.prod.deadorbit.net
echo 127.0.0.1 auth.signon.goliath.prod.gravityshavings.net
echo 127.0.0.1 api.signon.goliath.prod.deadorbit.net
echo 127.0.0.1 api.signon.goliath.prod.gravityshavings.net
echo 127.0.0.1 frontdoor-prod-client.fd.analytics.prod.deadorbit.net
echo 127.0.0.1 goliath.prod.gravityshavings.net
echo 127.0.0.1 goliath.prod.deadorbit.net
) >> "%HOSTS%"

echo [+] Successfully added all domain redirections to hosts file!
echo [*] Flushing DNS cache...
ipconfig /flushdns >nul
echo [+] DNS cache flushed. Ready for Marathon offline preservation.
pause
