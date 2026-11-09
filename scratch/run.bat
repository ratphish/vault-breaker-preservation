@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cl /nologo /EHsc d:\vault-breaker-preservation\scratch\test_thread_snapshot.cpp /Fe:d:\vault-breaker-preservation\scratch\test_thread_snapshot.exe /Fo:d:\vault-breaker-preservation\scratch\test_thread_snapshot.obj
d:\vault-breaker-preservation\scratch\test_thread_snapshot.exe
