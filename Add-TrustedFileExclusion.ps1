#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Adds a file-specific Defender exclusion then verifies the hash.

    For files already on disk that Defender has flagged as known threats,
    path exclusions do not reliably unblock file reads - the I/O filter
    still intercepts them even after Add-MpPreference. This script briefly
    disables real-time monitoring only for the hash computation (typically
    under one second), then immediately re-enables it. The file is not
    executed during this window.

    If the hash does not match the expected value, the exclusion is removed.

.PARAMETER FilePath
    Full path to the file to trust. Must already exist on disk.

.PARAMETER ExpectedHash
    SHA256 hash verified on VirusTotal or the official release page.

.PARAMETER PagerIP
    Tailscale IP of the Pager. Optional - omit to skip notification.

.PARAMETER PagerPort
    TCP port of the Pager netcat listener. Defaults to 9999.

.EXAMPLE
    .\Add-TrustedFileExclusion.ps1 `
        -FilePath     "F:\nanodump.x64.exe" `
        -ExpectedHash "AD9E4DDCE68A34F0BA3010E66286BC3AA056043C7DCA7A22C3222A279614025A"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$FilePath,

    [Parameter(Mandatory=$true)]
    [string]$ExpectedHash,

    [string]$PagerIP  = "",
    [int]$PagerPort   = 9999,
    [string]$RegistryPath = "$env:ProgramData\SecurityBaseline\trusted_hashes.json"
)

$ErrorActionPreference = "Stop"
$fileName     = Split-Path $FilePath -Leaf
$expectedNorm = $ExpectedHash.ToUpper().Trim()

Write-Host ""
Write-Host "File:     $FilePath"
Write-Host "Expected: $expectedNorm"
Write-Host ""

if (-not (Test-Path $FilePath)) {
    Write-Error "File not found: $FilePath"
    exit 1
}

# Add file-specific exclusion
Add-MpPreference -ExclusionPath $FilePath
Write-Host "[+] Exclusion added for: $FilePath" -ForegroundColor Cyan

# Compute hash
# The path exclusion is already in place. Wait for it to propagate
# before reading the file - Add-MpPreference returns before the
# Defender service has fully applied the exclusion.
Start-Sleep -Seconds 3

$actualHash = $null
try {
    $actualHash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash
} catch {
    Write-Host "[-] Hash computation failed: $_" -ForegroundColor Red
    Remove-MpPreference -ExclusionPath $FilePath -ErrorAction SilentlyContinue
    exit 1
}

Write-Host "Actual:   $actualHash"
Write-Host ""

if ($actualHash -ne $expectedNorm) {
    Write-Host "FAIL  Hash mismatch." -ForegroundColor Red
    Write-Host "      Removing exclusion - file is not trusted." -ForegroundColor Red
    Remove-MpPreference -ExclusionPath $FilePath -ErrorAction SilentlyContinue
    exit 1
}

Write-Host "PASS  Hash verified." -ForegroundColor Green
Write-Host "[+] Exclusion confirmed. Hash matches expected value." -ForegroundColor Green

# Set read-only (TOCTOU mitigation)
Set-ItemProperty -Path $FilePath -Name IsReadOnly -Value $true
Write-Host "[+] File set to read-only." -ForegroundColor Cyan

# Apply SACL - requires SeSecurityPrivilege enabled explicitly
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

# Write to hash registry
try {
    $dir = Split-Path $RegistryPath
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $reg = if (Test-Path $RegistryPath) {
        Get-Content $RegistryPath -Raw | ConvertFrom-Json
    } else { [PSCustomObject]@{} }
    $reg | Add-Member -NotePropertyName $FilePath -NotePropertyValue ([PSCustomObject]@{
        expectedHash = $expectedNorm
        fileName     = $fileName
        registeredAt = (Get-Date -Format "o")
    }) -Force
    $reg | ConvertTo-Json -Depth 5 | Set-Content $RegistryPath -Force
    Write-Host "[+] Registered in hash registry." -ForegroundColor Cyan
} catch {
    Write-Warning "Hash registry write failed: $_"
}

# Notify Pager if IP provided
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
