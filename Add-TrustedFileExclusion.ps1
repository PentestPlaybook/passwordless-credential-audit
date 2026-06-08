#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Downloads or locates a file, verifies its hash, prompts for confirmation,
    then applies a file-specific Defender exclusion and integrity monitoring.

.DESCRIPTION
    Workflow:
      1. If -URL is provided and the file does not exist, downloads it first.
         The Defender exclusion is added before the download so the file is
         not quarantined as it is written to disk.
      2. Computes the SHA256 hash of the file.
      3. If -ExpectedHash is provided, verifies the hash matches.
         Use this to confirm a file has not changed since it was last trusted.
      4. Displays the hash with a direct VirusTotal search link.
      5. Prompts: "Have you verified this hash on VirusTotal? (Y/N)"
      6. On Y: applies full protection - keeps exclusion, sets read-only,
         applies SACL (Event 4663 on write/delete), writes to hash registry,
         optionally notifies Pager.
      7. On N: removes exclusion and exits.

    GitHub blob URLs are converted to raw URLs automatically.

.PARAMETER FilePath
    Full path to the file. Used as the download destination if -URL is
    provided and the file does not exist.

.PARAMETER URL
    Optional download URL. GitHub blob URLs are accepted and converted
    to raw URLs automatically. If the file already exists, re-downloads
    and overwrites for integrity verification.

.PARAMETER ExpectedHash
    Optional. SHA256 to verify against. Use when re-trusting a file to
    confirm it has not changed since the last known good state.
    Does not replace the VirusTotal prompt.

.PARAMETER PagerIP
    Tailscale IP of the Pager. Optional - omit to skip notification.

.PARAMETER PagerPort
    TCP port of the Pager netcat listener. Defaults to 9999.

.EXAMPLE
    # Download and trust
    .\Add-TrustedFileExclusion.ps1 -FilePath "F:\nanodump.x64.exe" -URL "https://github.com/fortra/nanodump/blob/main/dist/nanodump.x64.exe"

    # Trust a file already on disk
    .\Add-TrustedFileExclusion.ps1 -FilePath "F:\nanodump.x64.exe"

    # Re-download and confirm hash has not changed
    .\Add-TrustedFileExclusion.ps1 -FilePath "F:\nanodump.x64.exe" -URL "https://..." -ExpectedHash "AD9E4D..."

    # With Pager notification
    .\Add-TrustedFileExclusion.ps1 -FilePath "F:\nanodump.x64.exe" -URL "https://..." -PagerIP "100.x.x.x"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$FilePath,

    [Parameter(Mandatory=$false)]
    [string]$URL = "",

    [Parameter(Mandatory=$false)]
    [string]$ExpectedHash = "",

    [string]$PagerIP  = "",
    [int]$PagerPort   = 9999,
    [string]$RegistryPath = "$env:ProgramData\SecurityBaseline\trusted_hashes.json"
)

$ErrorActionPreference = "Stop"
$fileName = Split-Path $FilePath -Leaf

Write-Host ""

# ── If FilePath is a directory and URL provided, derive filename from URL ─────
if ($URL -ne "" -and (Test-Path $FilePath -PathType Container)) {
    $urlFileName = Split-Path -Path ([System.Uri]$URL).LocalPath -Leaf
    $FilePath    = Join-Path (Resolve-Path $FilePath) $urlFileName
    $fileName    = $urlFileName
    Write-Host "[+] Directory provided - saving as: $FilePath" -ForegroundColor Cyan
}

# ── Download if URL provided ──────────────────────────────────────────────────
if ($URL -ne "") {

    # Convert GitHub blob URL to raw URL
    if ($URL -match '^https://github\.com/(.+)/blob/(.+)$') {
        $URL = "https://raw.githubusercontent.com/" + $Matches[1] + "/" + $Matches[2]
        Write-Host "[+] GitHub blob URL detected. Using raw URL:" -ForegroundColor Cyan
        Write-Host "    $URL" -ForegroundColor Cyan
        Write-Host ""
    }

    # Add exclusion BEFORE downloading so Defender does not quarantine
    # the file as it is written to disk
    Add-MpPreference -ExclusionPath $FilePath
    Start-Sleep -Seconds 3
    Write-Host "[+] Exclusion added for: $FilePath" -ForegroundColor Cyan

    # Clear read-only if file already exists
    if (Test-Path $FilePath) {
        Set-ItemProperty -Path $FilePath -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue
        Write-Host "[+] Overwriting existing file..." -ForegroundColor Cyan
    } else {
        Write-Host "[+] Downloading to $FilePath..." -ForegroundColor Cyan
    }

    try {
        Invoke-WebRequest -Uri $URL -OutFile $FilePath -UseBasicParsing -ErrorAction Stop
        Write-Host "[+] Download complete." -ForegroundColor Cyan
    } catch {
        Remove-MpPreference -ExclusionPath $FilePath -ErrorAction SilentlyContinue
        Write-Error "Download failed: $_"
        exit 1
    }

} elseif (-not (Test-Path $FilePath)) {
    Write-Error "File not found: $FilePath. Provide -URL to download it."
    exit 1
}

Write-Host "File: $FilePath"
Write-Host ""

# ── Add exclusion for FilePath mode (URL mode already added it above) ─────────
if ($URL -eq "") {
    Add-MpPreference -ExclusionPath $FilePath
    Start-Sleep -Seconds 3
}

# ── Compute hash ──────────────────────────────────────────────────────────────
$actualHash = $null
try {
    $actualHash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash
} catch {
    Write-Host "[-] Hash computation failed: $_" -ForegroundColor Red
    Remove-MpPreference -ExclusionPath $FilePath -ErrorAction SilentlyContinue
    exit 1
}

# ── Optional: verify against expected hash ────────────────────────────────────
if ($ExpectedHash -ne "") {
    $expectedNorm = $ExpectedHash.ToUpper().Trim()
    if ($actualHash -eq $expectedNorm) {
        Write-Host "[+] Hash matches expected value." -ForegroundColor Green
    } else {
        Write-Host "FAIL  Hash does not match expected value." -ForegroundColor Red
        Write-Host "      Expected: $expectedNorm" -ForegroundColor Red
        Write-Host "      Actual:   $actualHash" -ForegroundColor Red
        Write-Host "      Removing exclusion - file is not trusted." -ForegroundColor Red
        Remove-MpPreference -ExclusionPath $FilePath -ErrorAction SilentlyContinue
        exit 1
    }
}

# ── Display hash and VirusTotal link ──────────────────────────────────────────
Write-Host "SHA256: $actualHash" -ForegroundColor Cyan
Write-Host ""
Write-Host "Search this hash on VirusTotal:" -ForegroundColor Yellow
Write-Host "  https://www.virustotal.com/gui/search/$actualHash" -ForegroundColor Yellow
Write-Host ""
Write-Host "Do not use URL analysis - search by hash for the exact file you have." -ForegroundColor Yellow
Write-Host ""

# ── Prompt for confirmation ───────────────────────────────────────────────────
$confirm = Read-Host "Have you verified this hash on VirusTotal? (Y/N)"
if ($confirm -notmatch '^[Yy]$') {
    Write-Host ""
    Write-Host "[-] Cancelled. Removing exclusion." -ForegroundColor Yellow
    Remove-MpPreference -ExclusionPath $FilePath -ErrorAction SilentlyContinue
    exit 0
}

Write-Host ""
Write-Host "[+] Confirmed. Applying protection..." -ForegroundColor Green

# ── Set read-only (TOCTOU mitigation) ─────────────────────────────────────────
Set-ItemProperty -Path $FilePath -Name IsReadOnly -Value $true
Write-Host "[+] File set to read-only." -ForegroundColor Cyan

# ── Apply SACL - requires SeSecurityPrivilege enabled explicitly ──────────────
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class SACLHelper2 {
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool AdjustTokenPrivileges(
        IntPtr TokenHandle, bool DisableAll,
        ref TOKEN_PRIVILEGES2 NewState, uint Len,
        IntPtr Prev, IntPtr RetLen);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool LookupPrivilegeValue(
        string System, string Name, ref LUID2 Luid);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool OpenProcessToken(
        IntPtr Process, uint Access, out IntPtr Token);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();
    [StructLayout(LayoutKind.Sequential)]
    public struct LUID2 { public uint Lo; public int Hi; }
    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES2 {
        public uint Count; public LUID2 Luid; public uint Attributes; }
    public static bool Enable(string priv) {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), 0x28, out token)) return false;
        LUID2 luid = new LUID2();
        if (!LookupPrivilegeValue(null, priv, ref luid)) return false;
        TOKEN_PRIVILEGES2 tp = new TOKEN_PRIVILEGES2();
        tp.Count = 1; tp.Luid = luid; tp.Attributes = 0x2;
        return AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    }
}
"@
$null = [SACLHelper2]::Enable("SeSecurityPrivilege")

try {
    $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
        "Everyone",
        [System.Security.AccessControl.FileSystemRights]"Modify,Delete",
        [System.Security.AccessControl.InheritanceFlags]::None,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AuditFlags]::Success
    )
    $acl = [System.IO.File]::GetAccessControl(
        $FilePath,
        [System.Security.AccessControl.AccessControlSections]::Audit
    )
    $acl.AddAuditRule($rule)
    [System.IO.File]::SetAccessControl($FilePath, $acl)
    $null = & auditpol /set /subcategory:"File System" /success:enable /failure:enable 2>&1
    Write-Host "[+] SACL applied. Event 4663 will fire on write or delete." -ForegroundColor Cyan
} catch {
    Write-Warning "SACL could not be applied: $_"
}

# ── Write to hash registry ─────────────────────────────────────────────────────
try {
    $dir = Split-Path $RegistryPath
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $reg = if (Test-Path $RegistryPath) {
        Get-Content $RegistryPath -Raw | ConvertFrom-Json
    } else { [PSCustomObject]@{} }
    $reg | Add-Member -NotePropertyName $FilePath -NotePropertyValue ([PSCustomObject]@{
        expectedHash = $actualHash
        fileName     = $fileName
        registeredAt = (Get-Date -Format "o")
    }) -Force
    $reg | ConvertTo-Json -Depth 5 | Set-Content $RegistryPath -Force
    Write-Host "[+] Registered in hash registry." -ForegroundColor Cyan
} catch {
    Write-Warning "Hash registry write failed: $_"
}

# ── Notify Pager if IP provided ───────────────────────────────────────────────
if ($PagerIP -ne "") {
    try {
        $msg    = "EXCLUSION_ADDED: " + $fileName + " Hash verified"
        $client = New-Object System.Net.Sockets.TcpClient
        $client.ConnectAsync($PagerIP, $PagerPort).Wait(3000) | Out-Null
        if ($client.Connected) {
            $stream = $client.GetStream()
            $bytes  = [System.Text.Encoding]::UTF8.GetBytes($msg + "`n")
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush()
            $client.Close()
            Write-Host "[+] Pager notified." -ForegroundColor Cyan
        } else {
            Write-Warning "Pager connection timed out."
        }
    } catch {
        Write-Warning "Pager notification failed: $_"
    }
}

Write-Host ""
Write-Host "Done. $fileName is trusted at: $FilePath" -ForegroundColor Green
Write-Host "Exclusion scope: this file path only." -ForegroundColor Gray
