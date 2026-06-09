#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Monitors registered files for hash changes and fires Pager and ntfy
    alerts when a file's SHA256 no longer matches its registered value.

.DESCRIPTION
    Polls the hash registry written by Add-TrustedFileExclusion.ps1 on a
    configurable interval. For each registered file, computes the current
    SHA256 and compares against the stored expected value. Alerts fire only
    on actual hash changes or file deletion - not on every write attempt.

    This approach is independent of SACLs and Event 4663. File replacement
    removes any SACL on the original object, making event-driven detection
    unreliable. Hash polling detects the change regardless of how the file
    was modified or replaced.

.PARAMETER PagerIP
    Tailscale IP of the WiFi Pineapple Pager.

.PARAMETER PagerPort
    TCP port of the Pager netcat listener. Defaults to 9999.

.PARAMETER NtfyURL
    URL of the self-hosted ntfy instance.

.PARAMETER RegistryPath
    Path to trusted_hashes.json. Defaults to ProgramData\SecurityBaseline.

.PARAMETER IntervalSeconds
    How often to check each file. Defaults to 60 seconds.

.EXAMPLE
    .\Watch-FileIntegrity.ps1 `
        -PagerIP "100.x.x.x" `
        -NtfyURL "http://100.x.x.x:80/security-alerts"
#>

#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory=$true)]
    [string]$PagerIP,

    [int]$PagerPort = 9999,

    [Parameter(Mandatory=$true)]
    [string]$NtfyURL,

    [string]$RegistryPath = "$env:ProgramData\SecurityBaseline\trusted_hashes.json",

    [int]$IntervalSeconds = 60
)

# ── Alert functions ───────────────────────────────────────────────────────────
function Send-PagerAlert {
    param([string]$Message)
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $client.ConnectAsync($PagerIP, $PagerPort).Wait(3000) | Out-Null
        if ($client.Connected) {
            $stream = $client.GetStream()
            $bytes  = [System.Text.Encoding]::UTF8.GetBytes("$Message`n")
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush()
            $client.Close()
        }
    } catch {
        Write-Warning "Pager alert failed: $_"
    }
}

function Send-NtfyAlert {
    param([string]$Title, [string]$Body, [string]$Priority = "high")
    try {
        Invoke-RestMethod -Uri $NtfyURL `
            -Method POST `
            -Headers @{ "Title" = $Title; "Priority" = $Priority; "Tags" = "warning,file-integrity" } `
            -Body $Body `
            -ContentType "text/plain" | Out-Null
    } catch {
        Write-Warning "ntfy alert failed: $_"
    }
}

# ── Load hash registry ────────────────────────────────────────────────────────
function Get-Registry {
    if (-not (Test-Path $RegistryPath)) { return $null }
    try { return Get-Content $RegistryPath -Raw | ConvertFrom-Json }
    catch { return $null }
}

# ── Check a single file ───────────────────────────────────────────────────────
function Test-FileIntegrity {
    param([string]$FilePath, [string]$ExpectedHash, [string]$FileName)

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    if (-not (Test-Path $FilePath)) {
        $status = "FILE DELETED"
        $body   = @"
FILE DELETED
File:     $FileName
Path:     $FilePath
Expected: $ExpectedHash
Time:     $timestamp
"@
        Write-Host "[$timestamp] FILE DELETED - $FileName" -ForegroundColor Red
        Send-PagerAlert -Message "FILE_DELETED: $FileName"
        Send-NtfyAlert  -Title "File Deleted: $FileName" -Body $body -Priority "urgent"
        return
    }

    try {
        $actual = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash
    } catch {
        Write-Warning "Could not hash $FilePath`: $_"
        return
    }

    if ($actual -ne $ExpectedHash.ToUpper()) {
        $body = @"
INTEGRITY VIOLATION
File:     $FileName
Path:     $FilePath
Expected: $ExpectedHash
Actual:   $actual
Time:     $timestamp
"@
        Write-Host "[$timestamp] INTEGRITY VIOLATION - $FileName" -ForegroundColor Red
        Write-Host "             Expected: $ExpectedHash" -ForegroundColor Red
        Write-Host "             Actual:   $actual" -ForegroundColor Red
        Send-PagerAlert -Message "INTEGRITY_VIOLATION: $FileName hash changed"
        Send-NtfyAlert  -Title "Integrity Violation: $FileName" -Body $body -Priority "urgent"
    }
}

# ── Main polling loop ─────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[+] File Integrity Watcher starting..." -ForegroundColor Cyan
Write-Host "    Registry:  $RegistryPath" -ForegroundColor Cyan
Write-Host "    Pager:     $PagerIP`:$PagerPort" -ForegroundColor Cyan
Write-Host "    ntfy:      $NtfyURL" -ForegroundColor Cyan
Write-Host "    Interval:  $IntervalSeconds seconds" -ForegroundColor Cyan
Write-Host ""

while ($true) {
    $registry = Get-Registry

    if ($null -eq $registry) {
        Write-Host "[$((Get-Date -Format 'HH:mm:ss'))] Registry not found - waiting..." -ForegroundColor Yellow
    } else {
        $entries = $registry.PSObject.Properties
        foreach ($entry in $entries) {
            Test-FileIntegrity `
                -FilePath     $entry.Name `
                -ExpectedHash $entry.Value.expectedHash `
                -FileName     $entry.Value.fileName
        }
    }

    Start-Sleep -Seconds $IntervalSeconds
}
