# DLLHound - DLL Sideloading Scanner
# This script scans running processes and their loaded DLLs to identify potential DLL sideloading opportunities.
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
$VERY_SMALL_EXECUTABLE_SIZE = 50MB
$SMALL_EXECUTABLE_SIZE = 100MB
$STRICT_MAX_DLL_DEPENDENCIES = 10
$MAX_DLL_DEPENDENCIES = 50
$COMMON_SYSTEM_DLLS = @(
    'kernel32.dll', 'user32.dll', 'gdi32.dll', 'advapi32.dll', 'shell32.dll',
    'ole32.dll', 'oleaut32.dll', 'ntdll.dll', 'msvcrt.dll', 'ws2_32.dll'
)

# Function to extract imported DLLs from a PE file
function Get-ImportedDLLs {
    param ([string]$FilePath)
    try {
        $dllImports = @()
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        
        # Find .dll strings in the binary (simplified for this example)
        for ($i = 0; $i -lt $bytes.Length - 4; $i++) {
            if ($bytes[$i] -eq 0x2E -and # .
                $bytes[$i + 1] -eq 0x64 -and # d
                $bytes[$i + 2] -eq 0x6C -and # l
                $bytes[$i + 3] -eq 0x6C) { # l
                $start = $i
                while ($start -gt 0 -and $bytes[$start - 1] -ne 0) { $start-- }
                $dllName = [System.Text.Encoding]::ASCII.GetString($bytes[$start..($i + 3)])
                if ($dllName -match '^[a-zA-Z0-9_\-]+\.dll$') {
                    $dllImports += $dllName
                }
            }
        }
        return $dllImports | Select-Object -Unique
    } catch {
        Write-Host "Error reading ${FilePath}: $_" -ForegroundColor Red
        return @()
    }
}

# Function to test if a process is a likely target
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
    Write-Host "Starting DLL sideloading vulnerability scan..." -ForegroundColor Green
    
    $results = @()
    $processes = Get-Process | Where-Object { $_.MainModule }
    foreach ($process in $processes) {
        if ($ScanType -ne "Full" -and -not (Test-IsLikelyTarget -Process $process -StrictMode:($ScanType -eq "Strict") -CustomMode:($ScanType -eq "Custom") -CustomSize $CustomSize -CustomDLLs $CustomDLLs)) {
            continue
        }
        try {
            $processPath = $process.MainModule.FileName
            Write-Host "Scanning process: $($process.ProcessName)" -ForegroundColor Yellow
            $importedDLLs = Get-ImportedDLLs -FilePath $processPath
            $loadedDLLs = $process.Modules | Select-Object -ExpandProperty ModuleName
            $missingDLLs = $importedDLLs | Where-Object { $loadedDLLs -notcontains $_ }
            foreach ($dll in $missingDLLs) {
                $results += [PSCustomObject]@{
                    ProcessName = $process.ProcessName
                    ProcessId = $process.Id
                    ProcessPath = $processPath
                    MissingDLL = $dll
                }
            }
        } catch {
            Write-Host "Error scanning $($process.ProcessName): $_" -ForegroundColor Red
        }
    }

    if ($results.Count -gt 0) {
        Write-Host "Found DLL sideloading issues:" -ForegroundColor Yellow
        $results | Format-Table ProcessName, ProcessId, ProcessPath, MissingDLL -AutoSize
    } else {
        Write-Host "No DLL sideloading issues found." -ForegroundColor Green
    }
}

# User prompt
Write-Host "Select scan type:" -ForegroundColor Cyan
Write-Host "1: Full Scan"
Write-Host "2: Medium Scan (<100MB, <50 DLLs)"
Write-Host "3: Strict Scan (<50MB, <10 DLLs)"
Write-Host "4: Custom Scan (Define your own limits)"
$choice = Read-Host "Enter choice (1-4)"
switch ($choice) {
    "1" { Start-DLLSideloadingScan -ScanType "Full" }
    "2" { Start-DLLSideloadingScan -ScanType "Medium" }
    "3" { Start-DLLSideloadingScan -ScanType "Strict" }
    "4" { 
        $size = [int64](Read-Host "Enter maximum executable size in MB") * 1MB
        $dlls = [int](Read-Host "Enter maximum DLL dependencies")
        Start-DLLSideloadingScan -ScanType "Custom" -CustomSize $size -CustomDLLs $dlls
    }
    default { Write-Host "Invalid choice. Running Full Scan."; Start-DLLSideloadingScan -ScanType "Full" }
}
