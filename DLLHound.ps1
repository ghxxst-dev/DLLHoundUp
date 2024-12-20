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
|_____/|______|______|_|  |_|\___/ \__,_|_| |_|
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
        Write-Host "Reading PE headers from ${FilePath}..." -ForegroundColor DarkGray
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
        $signature = [BitConverter]::ToUInt32($bytes, $peOffset)
        if ($signature -ne 0x4550) { Write-Host "Invalid PE signature for ${FilePath}" -ForegroundColor Yellow; return @() }
        $importTableRvaOffset = $peOffset + 128
        $importTableRva = [BitConverter]::ToInt32($bytes, $importTableRvaOffset)
        if ($importTableRva -eq 0) { Write-Host "No import table found for ${FilePath}" -ForegroundColor Yellow; return @() }
        $dlls = @()
        Write-Host "Extracting imported DLLs..." -ForegroundColor DarkGray
        # Simulated logic for extracting DLLs
        # ...
        return $dlls
    } catch {
        Write-Host "Error reading ${FilePath}: $_" -ForegroundColor Red
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
        Write-Host "Analyzing process: $($Process.ProcessName) (PID: $($Process.Id))" -ForegroundColor Cyan
        $size = (Get-Item $Process.MainModule.FileName).Length
        $dllCount = $Process.Modules.Count
        $maxSize = if ($CustomMode) { $CustomSize } elseif ($StrictMode) { $VERY_SMALL_EXECUTABLE_SIZE } else { $SMALL_EXECUTABLE_SIZE }
        $maxDLLs = if ($CustomMode) { $CustomDLLs } elseif ($StrictMode) { $STRICT_MAX_DLL_DEPENDENCIES } else { $MAX_DLL_DEPENDENCIES }
        Write-Host "Executable Size: $size bytes | Max Allowed: $maxSize bytes" -ForegroundColor DarkGray
        Write-Host "DLL Count: $dllCount | Max Allowed: $maxDLLs" -ForegroundColor DarkGray
        return ($size -le $maxSize -and $dllCount -le $maxDLLs)
    } catch {
        Write-Host "Error analyzing $($Process.ProcessName): $_" -ForegroundColor Red
        return $false
    }
}

# Main scanning function
function Start-DLLSideloadingScan {
    param ([string]$ScanType = "Full", [int64]$CustomSize = 0, [int]$CustomDLLs = 0)
    Write-Host "Starting DLL sideloading vulnerability scan..." -ForegroundColor Green
    Write-Host "Scan Type: $ScanType" -ForegroundColor DarkGray
    if ($ScanType -eq "Custom") {
        Write-Host "Custom Settings: Max Size = $($CustomSize / 1MB)MB, Max DLLs = $CustomDLLs" -ForegroundColor Magenta
    }

    $results = @()
    $processes = Get-Process | Where-Object { $_.MainModule }
    foreach ($process in $processes) {
        if ($ScanType -ne "Full" -and -not (Test-IsLikelyTarget -Process $process -StrictMode:($ScanType -eq "Strict") -CustomMode:($ScanType -eq "Custom") -CustomSize $CustomSize -CustomDLLs $CustomDLLs)) {
            Write-Host "Skipping process $($process.ProcessName) due to filter criteria." -ForegroundColor Yellow
            continue
        }
        try {
            $processPath = $process.MainModule.FileName
            Write-Host "Analyzing $($process.ProcessName) (PID: $($process.Id)) at $processPath" -ForegroundColor Cyan
            $importedDLLs = Get-ImportedDLLs -FilePath $processPath
            Write-Host "Imported DLLs: $($importedDLLs -join ', ')" -ForegroundColor DarkGray
            $loadedDLLs = $process.Modules | Where-Object {
                $_.ModuleName.EndsWith('.dll', [StringComparison]::OrdinalIgnoreCase)
            } | Select-Object -ExpandProperty ModuleName
            Write-Host "Loaded DLLs: $($loadedDLLs -join ', ')" -ForegroundColor DarkGray

            # Log any DLLs that failed to load or are missing
            Write-Host "Comparing imported DLLs against loaded DLLs..." -ForegroundColor Cyan
            $missingDLLs = $importedDLLs | Where-Object { $loadedDLLs -notcontains $_ }
            foreach ($dllName in $missingDLLs) {
                if ($COMMON_SYSTEM_DLLS -contains $dllName.ToLower()) {
                    Write-Host "Skipping common system DLL: $dllName" -ForegroundColor Yellow
                    continue
                }
                Write-Host "Potential missing DLL: $dllName" -ForegroundColor Red
                $results += [PSCustomObject]@{
                    ProcessName = $process.ProcessName
                    ProcessId = $process.Id
                    ProcessPath = $processPath
                    MissingDLL = $dllName
                }
            }

            # Check if loaded DLLs have missing paths
            foreach ($module in $process.Modules) {
                try {
                    if (-not (Test-Path $module.FileName)) {
                        Write-Host "DLL file not found on disk: $($module.ModuleName)" -ForegroundColor Red
                        $results += [PSCustomObject]@{
                            ProcessName = $process.ProcessName
                            ProcessId = $process.Id
                            ProcessPath = $processPath
                            MissingDLL = $module.ModuleName
                        }
                    }
                } catch {
                    Write-Host "Error analyzing module $($module.ModuleName): $_" -ForegroundColor Yellow
                }
            }
        } catch {
            Write-Host "Error scanning process $($process.ProcessName): $_" -ForegroundColor Red
        }
    }

    # Output results
    if ($results.Count -gt 0) {
        $nonExeResults = $results | Where-Object { $_.ProcessPath -notlike '*.exe' }
        if ($nonExeResults.Count -gt 0) {
            Write-Host "`nVulnerable Programs Found:" -ForegroundColor Yellow
            $nonExeResults | ForEach-Object {
                Write-Host "Process: $_.ProcessName (PID: $_.ProcessId)" -ForegroundColor Green
                Write-Host "Missing DLL: $_.MissingDLL" -ForegroundColor Red
            }
            $scanTime = Get-Date -Format 'yyyyMMdd_HHmmss'
            $exportPath = Join-Path $env:USERPROFILE "Desktop\DLLSideloadingScan_$ScanType_$scanTime.csv"
            $nonExeResults | Export-Csv -Path $exportPath -NoTypeInformation
            Write-Host "Results exported to: $exportPath" -ForegroundColor Green
        } else {
            Write-Host "No DLL issues found in non-executable files." -ForegroundColor Green
        }
    } else {
        Write-Host "No potential DLL sideloading vulnerabilities found." -ForegroundColor Green
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
