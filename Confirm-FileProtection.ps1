#Requires -RunAsAdministrator
param(
    [Parameter(Mandatory=$true)]
    [string]$FilePath,
    [string]$RegistryPath = "$env:ProgramData\SecurityBaseline\trusted_hashes.json"
)

$FilePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FilePath)
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
    Write-Host "[FAIL] Drive $driveLetter is $fsType - NTFS required." -ForegroundColor Red
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

# 5. DACL - Users group should have Read only, not Write or Execute
try {
    $acl   = Get-Acl -Path $FilePath
    $rules = $acl.Access | Where-Object { $_.IdentityReference -match "Users" }
    if ($rules) {
        $hasWrite = $rules | Where-Object {
            $_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Write
        }
        if ($hasWrite) {
            Write-Host "[FAIL] Users group has Write permission - overwrite attack possible." -ForegroundColor Red
        } else {
            Write-Host "[PASS] Users group restricted to Read - no overwrite path." -ForegroundColor Green
        }
    } else {
        Write-Host "[WARN] No explicit Users ACE found - verify DACL manually." -ForegroundColor Yellow
    }
} catch {
    Write-Host "[WARN] Could not read DACL: $_" -ForegroundColor Yellow
}

# 6. Hash registry
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

# 7. Current hash vs registry
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
