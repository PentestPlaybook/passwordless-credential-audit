#Requires -RunAsAdministrator
param(
    [Parameter(Mandatory=$true)]
    [string]$FilePath,
    [string]$RegistryPath = "$env:ProgramData\SecurityBaseline\trusted_hashes.json"
)

$fileName = Split-Path $FilePath -Leaf

Write-Host ""
Write-Host "Verifying: $FilePath" -ForegroundColor Cyan
Write-Host "------------------------------------------------------------"

# 1. File exists
if (Test-Path $FilePath) {
    Write-Host "[PASS] File exists." -ForegroundColor Green
} else {
    Write-Host "[FAIL] File not found." -ForegroundColor Red
    exit 1
}

# 2. Filesystem is NTFS
$driveLetter = (Split-Path $FilePath -Qualifier).TrimEnd(":")
$fsType = (Get-Volume -DriveLetter $driveLetter -ErrorAction SilentlyContinue).FileSystemType
if ($fsType -eq "NTFS") {
    Write-Host "[PASS] Drive $driveLetter is NTFS." -ForegroundColor Green
} else {
    Write-Host "[FAIL] Drive $driveLetter is $fsType - SACLs require NTFS." -ForegroundColor Red
}

# 3. Read-only flag
$item = Get-Item $FilePath
if ($item.IsReadOnly) {
    Write-Host "[PASS] Read-only flag set." -ForegroundColor Green
} else {
    Write-Host "[FAIL] Read-only flag not set." -ForegroundColor Red
}

# 4. Defender exclusion
$excls = (Get-MpPreference).ExclusionPath
if ($excls -contains $FilePath) {
    Write-Host "[PASS] Defender exclusion present." -ForegroundColor Green
} else {
    Write-Host "[FAIL] No Defender exclusion found for this path." -ForegroundColor Red
}

# 5. SACL audit rule
$auditRules = $null
try {
    $auditRules = (Get-Acl -Path $FilePath -Audit).Audit
} catch {
    Write-Host "[WARN] Could not read SACL: $_" -ForegroundColor Yellow
}
if ($null -ne $auditRules -and $auditRules.Count -gt 0) {
    Write-Host "[PASS] SACL applied:" -ForegroundColor Green
    foreach ($r in $auditRules) {
        Write-Host "       Rights=$($r.FileSystemRights)  Flags=$($r.AuditFlags)  Principal=$($r.IdentityReference)" -ForegroundColor Gray
    }
} else {
    Write-Host "[FAIL] SACL empty - Event 4663 will not fire." -ForegroundColor Red
}

# 6. File System audit subcategory
$pol = & auditpol /get /subcategory:"File System" 2>&1 | Out-String
if ($pol -match "Success") {
    Write-Host "[PASS] File System audit subcategory enabled." -ForegroundColor Green
} else {
    Write-Host "[FAIL] File System audit subcategory not enabled." -ForegroundColor Red
}

# 7. Hash registry
if (Test-Path $RegistryPath) {
    $reg = Get-Content $RegistryPath -Raw | ConvertFrom-Json
    $entry = $reg.PSObject.Properties | Where-Object { $_.Name -eq $FilePath }
    if ($null -ne $entry) {
        Write-Host "[PASS] Hash registry entry found." -ForegroundColor Green
        Write-Host "       Hash=$($entry.Value.expectedHash)" -ForegroundColor Gray
        Write-Host "       Registered=$($entry.Value.registeredAt)" -ForegroundColor Gray
    } else {
        Write-Host "[WARN] No hash registry entry - Watch-FileIntegrity.ps1 will not monitor this file." -ForegroundColor Yellow
    }
} else {
    Write-Host "[WARN] Hash registry file not found at $RegistryPath" -ForegroundColor Yellow
}

# 8. Current hash vs registry
$currentHash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash
Write-Host ""
Write-Host "Current SHA256: $currentHash" -ForegroundColor Cyan
if (Test-Path $RegistryPath) {
    $reg = Get-Content $RegistryPath -Raw | ConvertFrom-Json
    $entry = $reg.PSObject.Properties | Where-Object { $_.Name -eq $FilePath }
    if ($null -ne $entry) {
        if ($currentHash -eq $entry.Value.expectedHash) {
            Write-Host "[PASS] Hash matches registry - integrity confirmed." -ForegroundColor Green
        } else {
            Write-Host "[FAIL] Hash does NOT match registry." -ForegroundColor Red
        }
    }
}

Write-Host "------------------------------------------------------------"
Write-Host ""
