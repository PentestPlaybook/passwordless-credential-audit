# Security Research Tool Protection Suite

PowerShell scripts for managing Windows Defender exclusions, file integrity
monitoring, and out-of-band alerting for known-signature security research tools.

Built for a Windows 11 home lab running OSCP / CPTS study and penetration
testing research. Designed to apply the principle of least privilege at the
Defender exclusion layer and integrate file integrity events into a SIEM/SOAR
notification pipeline via the WiFi Pineapple Pager.

---

## Architecture

```
Add-TrustedFileExclusion.ps1
    Hash verified against VirusTotal value
        File-specific Defender exclusion (not directory)
        Read-only flag (TOCTOU mitigation)
        SACL applied (Event 4663 on write/delete)
        Hash registered in trusted_hashes.json

Watch-FileIntegrity.ps1 (persistent, runs at startup)
    Monitors Event 4663 on registered file paths
        Hash changed  -> INTEGRITY VIOLATION (urgent)
        File deleted  -> FILE DELETED (urgent)
        Write blocked -> WRITE ATTEMPT (high)
            Pager TCP alert via soar_listener.sh
            ntfy push notification to phone

Confirm-FileProtection.ps1
    8-point spot-check of all protection components
```

---

## Prerequisites

- **Windows 11, PowerShell 5.1+, elevated session** (`#Requires -RunAsAdministrator`)
- **NTFS filesystem** on the target drive - SACLs are not supported on exFAT or FAT32
- **WiFi Pineapple Pager** with `soar_listener.sh` running (for Pager alerts)
- **ntfy** self-hosted on Mac Mini via Tailscale (for phone push notifications)
- **Tailscale** enrolled on both Aurora and Pager for stable IP addressing

---

## Scripts

### `Add-TrustedFileExclusion.ps1`

Verifies a file's SHA256 hash and applies the full protection stack.

**Parameters:**
| Parameter | Required | Description |
|---|---|---|
| `-FilePath` | Yes | Full path to the file. Used as download destination if file does not exist and -URL is provided. Accepts a directory - filename derived from URL. |
| `-URL` | No | Download URL. GitHub blob URLs converted automatically. If file exists, re-downloads and overwrites for integrity verification. |
| `-ExpectedHash` | No | SHA256 safety check. Verifies the file has not changed since last known state. Does not replace the VirusTotal prompt. |
| `-PagerIP` | No | Tailscale IP of the Pager - omit to skip notification |
| `-PagerPort` | No | Pager netcat listener port (default: 9999) |

**What it does:**
1. Adds a file-specific Defender exclusion scoped to the exact path
2. Waits 3 seconds for the exclusion to propagate
3. Computes SHA256 hash (real-time monitoring remains active)
4. Compares hash against expected value
5. **Match:** sets read-only, applies SACL, writes to hash registry, notifies Pager
6. **Mismatch:** removes exclusion immediately - nothing trusted, nothing left behind

**Usage:**
```powershell
# File already on disk
.\Add-TrustedFileExclusion.ps1 -FilePath "F:\nanodump.x64.exe"

# Download from URL to specific path (GitHub blob or raw URLs accepted)
.\Add-TrustedFileExclusion.ps1 -FilePath "F:\" -URL "https://github.com/fortra/nanodump/blob/main/dist/nanodump.x64.exe"
.\Add-TrustedFileExclusion.ps1 -FilePath "F:\mimikatz.exe" -URL "https://github.com/ParrotSec/mimikatz/blob/master/x64/mimikatz.exe"

# With Pager notification
.\Add-TrustedFileExclusion.ps1 -FilePath "F:\mimikatz.exe" -URL "https://github.com/ParrotSec/mimikatz/blob/master/x64/mimikatz.exe" -PagerIP "100.x.x.x"

# Re-download and verify hash has not changed since last known state
.\Add-TrustedFileExclusion.ps1 -FilePath "F:\nanodump.x64.exe" -URL "https://github.com/fortra/nanodump/blob/main/dist/nanodump.x64.exe" -ExpectedHash "AD9E4DDCE68A34F0BA3010E66286BC3AA056043C7DCA7A22C3222A279614025A"
.\Add-TrustedFileExclusion.ps1 -FilePath "F:\mimikatz.exe" -URL "https://github.com/ParrotSec/mimikatz/blob/master/x64/mimikatz.exe" -ExpectedHash "92804FAAAB2175DC501D73E814663058C78C0A042675A8937266357BCFB96C50"

```

**Getting the expected hash:**

VirusTotal URL analysis caches results and may reflect a file from months or
years ago. If the repo has been updated since the last analysis, the cached
hash will not match the file you downloaded.

The correct workflow is:

1. Download the file
2. Compute its hash (briefly disable real-time monitoring for known-signature tools)
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
(Get-FileHash "F:\nanodump.x64.exe").Hash
Set-MpPreference -DisableRealtimeMonitoring $false
```
3. Paste that hash into [virustotal.com](https://virustotal.com) search
4. Review the detection report for the exact file you have
5. Run `Add-TrustedFileExclusion.ps1` with that hash as `-ExpectedHash`

If you use VirusTotal's URL analysis instead of a hash search, click
**Reanalyze** first to force a fresh fetch — otherwise the cached hash
may not match the current file at that URL.

Raw GitHub URL format (blob URL → raw URL):
```
github.com/{user}/{repo}/blob/{branch}/{path}
                 ↓
raw.githubusercontent.com/{user}/{repo}/{branch}/{path}
```

**Note on directory exclusions:**
This script adds a file-path exclusion, not a directory exclusion. A directory
exclusion creates a trusted execution zone that any file benefits from - including
files an attacker places there. A file-path exclusion trusts exactly one artifact.
Nothing else at that path benefits from it.

---

### `Watch-FileIntegrity.ps1`

Persistent watcher that monitors Event 4663 on registered file paths and fires
Pager and ntfy alerts when a write or delete attempt is detected.

**Parameters:**
| Parameter | Required | Description |
|---|---|---|
| `-PagerIP` | Yes | Tailscale IP of the Pager |
| `-PagerPort` | No | Pager netcat listener port (default: 9999) |
| `-NtfyURL` | Yes | URL of the self-hosted ntfy instance |
| `-RegistryPath` | No | Path to trusted_hashes.json (default: ProgramData\SecurityBaseline) |

**Usage:**
```powershell
.\Watch-FileIntegrity.ps1 `
    -PagerIP "100.x.x.x" `
    -NtfyURL "http://100.x.x.x:80/security-alerts"
```

**Run at startup (recommended):**
```powershell
$action  = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NonInteractive -WindowStyle Hidden -File C:\Scripts\Watch-FileIntegrity.ps1 -PagerIP 100.x.x.x -NtfyURL http://100.x.x.x:80/security-alerts"
$trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName "FileIntegrityWatcher" `
    -Action $action -Trigger $trigger -RunLevel Highest -User "SYSTEM"
```

**Alert format:**
```
[EMOJI] FILE INTEGRITY ALERT
File:     nanodump.x64.exe
Path:     F:\nanodump.x64.exe
Status:   INTEGRITY VIOLATION - HASH CHANGED
Process:  cmd.exe (PID 4892)
Expected: AD9E4D...
Actual:   B7F2A1...
SOAR:     NOT REMEDIATED
Time:     2026-06-07 14:32:15
```

---

### `Confirm-FileProtection.ps1`

Eight-point verification of all protection components on a registered file.
Run after `Add-TrustedFileExclusion.ps1` to confirm everything is in place,
and before and after integrity violation tests.

**Usage:**
```powershell
.\Confirm-FileProtection.ps1 -FilePath "F:\nanodump.x64.exe"
```

**Checks:**
1. File exists on disk
2. Drive is NTFS (required for SACL support)
3. Read-only flag is set
4. Defender exclusion is present for this exact path
5. SACL audit rule is applied (Event 4663 will fire)
6. File System audit subcategory is enabled
7. Hash registry entry exists
8. Current hash matches registry value

---

### `soar_listener.sh` (Pager side)

Runs on the WiFi Pineapple Pager. Listens on TCP port 9999 for messages from
the Aurora SOAR pipeline and triggers DuckyScript ALERT + VIBRATE.

**Installation:**
```sh
scp soar_listener.sh root@<pager-ip>:/root/scripts/
ssh root@<pager-ip> "chmod +x /root/scripts/soar_listener.sh"
```

Add to `/etc/rc.local` to run at boot:
```sh
/root/scripts/soar_listener.sh &
```

**Message routing:**
- `EXCLUSION_ADDED:` prefix uses the dedicated exclusion alert payload
- All other messages use the generic alert handler

---

## End-to-End Test

To verify the full pipeline is working:

```powershell
# 1. Confirm baseline state
.\Confirm-FileProtection.ps1 -FilePath "F:\nanodump.x64.exe"

# 2. Start the watcher in a separate terminal
.\Watch-FileIntegrity.ps1 -PagerIP "100.x.x.x" -NtfyURL "http://100.x.x.x:80/security-alerts"

# 3. Trigger an integrity violation
Set-ItemProperty "F:\nanodump.x64.exe" -Name IsReadOnly -Value $false
"fake" | Set-Content "F:\nanodump.x64.exe" -Force

# Pager should buzz and phone should receive:
# INTEGRITY VIOLATION - HASH CHANGED | NOT REMEDIATED

# 4. Restore the original file and re-run Add-TrustedFileExclusion.ps1
```

---

## Security Design Notes

**Least privilege at the exclusion layer**
Defender path exclusions are scoped to a single file, not a directory. An attacker
with an admin shell who knows the exclusion exists cannot use it as a trusted
execution zone for other tools.

**TOCTOU mitigation**
Files are set read-only immediately after hash verification. Replacing the verified
file with a malicious one requires clearing the read-only attribute first, which
is an additional privileged step that itself generates a detectable event.

**SACL and SeSecurityPrivilege**
Applying SACLs requires SeSecurityPrivilege to be explicitly enabled via
AdjustTokenPrivileges. PowerShell's Set-Acl does not activate this privilege
automatically even in an elevated session. The script handles this via P/Invoke.

**NTFS requirement**
SACLs are an NTFS feature. ExFAT and FAT32 drives do not support security
descriptors. External SSDs are commonly formatted exFAT for cross-platform
compatibility and must be reformatted to NTFS before file integrity monitoring
can be applied to files stored on them. Use `convert F: /fs:ntfs` for FAT32
drives; exFAT drives must be formatted (data will be lost - back up first).

**Out-of-band notification**
Alerts route through the Pager and phone via a TCP connection to the Pager's
netcat listener, operating independently of the Aurora's security state. An
attacker who disables Sysmon or Defender on the Aurora cannot suppress these
notifications.

---

## File Layout

```
C:\ProgramData\SecurityBaseline\
    trusted_hashes.json          Hash registry for Watch-FileIntegrity.ps1

/root/scripts/soar_listener.sh   Pager - TCP listener and alert trigger
/root/payloads/alerts/exclusion/
    payload.ds                   DuckyScript for exclusion-added alerts
```

> Note: `Invoke-SecureDownload.ps1` is superseded. URL download is now
> handled directly by `Add-TrustedFileExclusion.ps1` via the `-URL` parameter.
