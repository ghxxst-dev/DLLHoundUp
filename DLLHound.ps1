# DLLHound - DLL Sideloading Scanner
# Author: @ajm4n
# Description: Scans processes for potential DLL sideloading vulnerabilities
# Requires running with administrator privileges
#Requires -RunAsAdministrator

# ASCII art title
Write-Host @"
 _____  _      _      _    _                       _ 
|  __ \| |    | |    | |  | |                     | |
| |  | | |    | |    | |__| | ___  _   _ _ __   __| |
| |  | | |    | |    |  __  |/ _ \| | | | '_ \ / _  |
| |__| | |____| |____| |  | | (_) | |_| | | | | (_| |
|_____/|______|______|_|  |_|\___/ \__,_|_| |_|\__,_|
                        by @ajm4n
"@ -ForegroundColor Cyan

# Configuration
$VERY_SMALL_EXECUTABLE_SIZE = 50MB  # Maximum size for strict targeted scan
$SMALL_EXECUTABLE_SIZE = 100MB      # Maximum size for medium targeted scan
$STRICT_MAX_DLL_DEPENDENCIES = 10   # Maximum DLL dependencies for strict targeted scan
$MAX_DLL_DEPENDENCIES = 50          # Maximum DLL dependencies for medium targeted scan

$COMMON_SYSTEM_DLLS = @(
    'kernel32.dll', 'user32.dll', 'gdi32.dll', 'advapi32.dll', 'shell32.dll',
    'ole32.dll', 'oleaut32.dll', 'ntdll.dll', 'msvcrt.dll', 'ws2_32.dll'
)

# Function to extract imported DLLs from a PE file
function Get-ImportedDLLs {
    param ([string]$FilePath)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
        $signature = [BitConverter]::ToUInt32($bytes, $peOffset)
        if ($signature -ne 0x4550) { return @() } # Invalid PE signature
        $importTableRvaOffset = $peOffset + 128
        $importTableRva = [BitConverter]::ToInt32($bytes, $importTableRvaOffset)
        if ($importTableRva -eq 0) { return @() } # No imports
        $dlls = @()
        # Simulated logic for extracting DLLs
        # ...
        return $dlls
    } catch {
        Write-Host "Error reading $FilePath: $_" -ForegroundColor Red
        return @()
    }
}

# Function to validate likely targets
function Test-IsLikelyTarget {
    param (
        [System.Diagnostics.Process]$Process,
        [switch]$StrictMode,
        [switch]$CustomMode,
        [int64]$CustomSize = 0,
        [int]$CustomDLLs = 0
    )
    try {
        $size = (Get-Item $Process.MainModule.FileName).Length
        $dllCount = $Process.Modules.Count
        $maxSize = if ($CustomMode) { $CustomSize } elseif ($StrictMode) { $VERY_SMALL_EXECUTABLE_SIZE } else { $SMALL_EXECUTABLE_SIZE }
        $maxDLLs = if ($CustomMode) { $CustomDLLs } elseif ($StrictMode) { $STRICT_MAX_DLL_DEPENDENCIES } else { $MAX_DLL_DEPENDENCIES }
        return ($size -le $maxSize -and $dllCount -le $maxDLLs)
    } catch {
        Write-Host "Error analyzing $($Process.ProcessName): $_" -ForegroundColor Red
        return $false
    }
}

# Main scanning function
function Start-DLLSideloadingScan {
    param ([string]$ScanType = "Full", [int64]$CustomSize = 0, [int]$CustomDLLs = 0)
    $processes = Get-Process | Where-Object { $_.MainModule }
    foreach ($process in $processes) {
        if ($ScanType -ne "Full" -and -not (Test-IsLikelyTarget -Process $process -StrictMode:($ScanType -eq "Strict") -CustomMode:($ScanType -eq "Custom") -CustomSize $CustomSize -CustomDLLs $CustomDLLs)) {
            continue
        }
        # Scan logic here...
    }
}

# User prompt
Write-Host "Select scan type:" -ForegroundColor Cyan
Write-Host "1: Full Scan (All Applications)"
Write-Host "2: Medium Scan (<100MB, <50 DLLs)"
Write-Host "3: Strict Scan (<50MB, <10 DLLs)"
Write-Host "4: Custom Scan (Define limits)"
$choice = Read-Host "Enter choice (1-4)"
switch ($choice) {
    "1" { Start-DLLSideloadingScan -ScanType "Full" }
    "2" { Start-DLLSideloadingScan -ScanType "Medium" }
    "3" { Start-DLLSideloadingScan -ScanType "Strict" }
    "4" { 
        $size = [int64](Read-Host "Max size (MB)") * 1MB
        $dlls = [int](Read-Host "Max DLLs")
        Start-DLLSideloadingScan -ScanType "Custom" -CustomSize $size -CustomDLLs $dlls
    }
    default { Write-Host "Invalid choice. Running full scan."; Start-DLLSideloadingScan -ScanType "Full" }
}
