<#
.SYNOPSIS
    Monitors registered research tool files for integrity violations and fires
    Pager and ntfy push alerts when a write or delete attempt is detected.

.DESCRIPTION
    Watches the Windows Security event log for Event 4663 (file object access)
    against paths registered by Invoke-SecureDownload.ps1. On each event:

      1. Identifies which registered file triggered the alert
      2. Checks whether the file still exists
      3. Computes the current SHA256 hash if the file is present
      4. Compares against the expected hash stored in the registry
      5. Fires a Pager TCP alert (via netcat listener on the Pager) and an
         ntfy push notification with full details:
           - File path and name
           - Process that attempted the access
           - Whether the hash changed (INTEGRITY VIOLATION) or not (attempt blocked)
           - Remediation status

    The Pager alert uses a simple TCP connection (Layer 4) to the Pager's
    netcat listener on port 9999. The listener pipes received messages to
    syslog via logger, and a syslog watcher on the Pager triggers the
    DuckyScript ALERT. No SSH key infrastructure required.

    Runs as a persistent background watcher. Register as a scheduled task at
    startup to ensure continuous coverage.

.PARAMETER PagerIP
    IP address of the WiFi Pineapple Pager on the Tailscale network.

.PARAMETER PagerPort
    TCP port of the netcat listener on the Pager. Defaults to 9999.

.PARAMETER NtfyURL
    URL of the self-hosted ntfy instance (e.g. http://100.x.x.x:80/security-alerts).

.PARAMETER RegistryPath
    Path to the trusted_hashes.json file written by Invoke-SecureDownload.ps1.
    Defaults to $env:ProgramData\SecurityBaseline\trusted_hashes.json.

.EXAMPLE
    .\Watch-FileIntegrity.ps1 `
        -PagerIP   "100.x.x.x" `
        -NtfyURL   "http://100.x.x.x:80/security-alerts"
#>

#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory=$true)]
    [string]$PagerIP,

    [int]$PagerPort = 9999,

    [Parameter(Mandatory=$true)]
    [string]$NtfyURL,

    [string]$RegistryPath = "$env:ProgramData\SecurityBaseline\trusted_hashes.json"
)

# ── Load hash registry ────────────────────────────────────────────────────────
function Get-HashRegistry {
    if (-not (Test-Path $RegistryPath)) {
        Write-Warning "Hash registry not found at $RegistryPath"
        Write-Warning "Run Invoke-SecureDownload.ps1 first to register files."
        return $null
    }
    return Get-Content $RegistryPath -Raw | ConvertFrom-Json
}

# ── Alert functions ───────────────────────────────────────────────────────────
function Send-PagerAlert {
    param([string]$EventType, [string]$Message)
    # Sends a plain TCP message to the Pager's netcat listener on port 9999.
    # The Pager pipes the message to syslog via logger, and a syslog watcher
    # triggers the DuckyScript ALERT. No SSH or key management required.
    # Layer stack: .NET TcpClient (L7) → TCP (L4) → IP/Tailscale (L3) → L1/2
    try {
        $payload = "$EventType`: $Message"
        $client  = New-Object System.Net.Sockets.TcpClient
        $client.ConnectAsync($PagerIP, $PagerPort).Wait(3000) | Out-Null
        if ($client.Connected) {
            $stream = $client.GetStream()
            $bytes  = [System.Text.Encoding]::UTF8.GetBytes("$payload`n")
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush()
            $client.Close()
        } else {
            Write-Warning "Pager TCP connection timed out ($PagerIP`:$PagerPort)"
        }
    } catch {
        Write-Warning "Pager alert failed: $_"
    }
}

function Send-NtfyAlert {
    param(
        [string]$Title,
        [string]$Body,
        [string]$Priority = "high"
    )
    try {
        Invoke-RestMethod -Uri $NtfyURL `
            -Method POST `
            -Headers @{
                "Title"    = $Title
                "Priority" = $Priority
                "Tags"     = "warning,file-integrity"
            } `
            -Body $Body `
            -ContentType "text/plain" | Out-Null
    } catch {
        Write-Warning "ntfy alert failed: $_"
    }
}

# ── Handle an Event 4663 hit ──────────────────────────────────────────────────
function Invoke-IntegrityAlert {
    param([System.Diagnostics.Eventing.Reader.EventLogRecord]$Event)

    # Parse event XML for fields
    $xml        = [xml]$Event.ToXml()
    $data       = $xml.Event.EventData.Data
    $objectName = ($data | Where-Object { $_.Name -eq "ObjectName" }).'#text'
    $processNm  = ($data | Where-Object { $_.Name -eq "ProcessName" }).'#text'
    $subject    = ($data | Where-Object { $_.Name -eq "SubjectUserName" }).'#text'
    $accessList = ($data | Where-Object { $_.Name -eq "AccessList" }).'#text'
    $timestamp  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Reload registry in case new files were registered since watcher started
    $registry = Get-HashRegistry
    if (-not $registry) { return }

    # Check if this path is one we're monitoring
    $entry = $registry.PSObject.Properties | Where-Object { $_.Name -eq $objectName }
    if (-not $entry) { return }

    $expectedHash = $entry.Value.expectedHash
    $fileName     = $entry.Value.fileName

    # Determine integrity status
    if (-not (Test-Path $objectName)) {
        $status      = "FILE DELETED"
        $actualHash  = "N/A (file removed)"
        $statusEmoji = "❌"
        $priority    = "urgent"
        $soarStatus  = "NOT REMEDIATED"
    } else {
        $actualHash = (Get-FileHash -Path $objectName -Algorithm SHA256).Hash
        if ($actualHash -eq $expectedHash) {
            $status      = "WRITE ATTEMPT - HASH UNCHANGED"
            $statusEmoji = "✅"
            $priority    = "high"
            $soarStatus  = "REMEDIATED (read-only blocked modification)"
        } else {
            $status      = "INTEGRITY VIOLATION - HASH CHANGED"
            $statusEmoji = "❌"
            $priority    = "urgent"
            $soarStatus  = "NOT REMEDIATED"
        }
    }

    # ── Build notification body ───────────────────────────────────────────────
    $ntfyBody = @"
$statusEmoji FILE INTEGRITY ALERT
File:     $fileName
Path:     $objectName
Status:   $status
Process:  $processNm
User:     $subject
Expected: $expectedHash
Actual:   $actualHash
SOAR:     $soarStatus
Time:     $timestamp
"@

    $pagerMsg = "$status | $fileName | $processNm"

    # ── Fire alerts ───────────────────────────────────────────────────────────
    Write-Host "[$timestamp] $status — $fileName" -ForegroundColor $(
        if ($soarStatus -eq "NOT REMEDIATED") { "Red" } else { "Yellow" }
    )

    Send-PagerAlert -EventType "FILE_INTEGRITY" -Message $pagerMsg
    Send-NtfyAlert  -Title "$statusEmoji File Integrity Alert" -Body $ntfyBody -Priority $priority
}

# ── Set up EventLogWatcher on Security log ────────────────────────────────────
# XPath query: Event 4663, ObjectType = File only
$query = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[EventID=4663]
        and EventData[Data[@Name='ObjectType']='File']]
    </Select>
  </Query>
</QueryList>
"@

Write-Host ""
Write-Host "[+] File Integrity Watcher starting..." -ForegroundColor Cyan
Write-Host "    Registry: $RegistryPath" -ForegroundColor Cyan
Write-Host "    Pager:    $PagerIP" -ForegroundColor Cyan
Write-Host "    ntfy:     $NtfyURL" -ForegroundColor Cyan

$registry = Get-HashRegistry
if ($registry) {
    $monitored = $registry.PSObject.Properties.Name
    Write-Host "    Monitoring $($monitored.Count) file(s):" -ForegroundColor Cyan
    $monitored | ForEach-Object { Write-Host "      - $_" -ForegroundColor Gray }
}

Write-Host ""
Write-Host "[+] Watching for Event 4663... (Ctrl+C to stop)" -ForegroundColor Green
Write-Host ""

try {
    $evtQuery   = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery("Security",
                    [System.Diagnostics.Eventing.Reader.PathType]::LogName, $query)
    $watcher    = New-Object System.Diagnostics.Eventing.Reader.EventLogWatcher($evtQuery)

    $watcher.add_EventRecordWritten({
        param($sender, $args)
        if ($args.EventRecord) {
            Invoke-IntegrityAlert -Event $args.EventRecord
        }
    })

    $watcher.Enabled = $true

    # Keep the script alive
    while ($true) { Start-Sleep -Seconds 5 }

} catch {
    Write-Error "Watcher failed: $_"
} finally {
    if ($watcher) { $watcher.Dispose() }
}
