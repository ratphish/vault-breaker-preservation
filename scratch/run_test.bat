@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "%~dp0"
cl /nologo /O2 test_crc.cpp /Fe:test_crc.exe >nul
if %ERRORLEVEL% equ 0 (
    test_crc.exe
) else (
    echo Compilation failed.
)
