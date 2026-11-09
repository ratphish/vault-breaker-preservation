@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cl /nologo /EHsc d:\vault-breaker-preservation\scratch\test_bcrypt.cpp /Fe:d:\vault-breaker-preservation\scratch\test_bcrypt.exe /Fo:d:\vault-breaker-preservation\scratch\test_bcrypt.obj bcrypt.lib
d:\vault-breaker-preservation\scratch\test_bcrypt.exe
