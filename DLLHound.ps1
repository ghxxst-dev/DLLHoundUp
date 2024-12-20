# Enhanced DLL Sideloading Scanner - Spartacus-style
# Scans processes for missing or unresolved DLLs using dynamic analysis

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
                  by @ajm4n - Inspired by Spartacus
"@ -ForegroundColor Cyan

# Configuration
$COMMON_SYSTEM_DLLS = @(
    'kernel32.dll', 'user32.dll', 'gdi32.dll', 'advapi32.dll', 'shell32.dll',
    'ole32.dll', 'oleaut32.dll', 'ntdll.dll', 'msvcrt.dll', 'ws2_32.dll'
)
$STANDARD_WINDOWS_PROCESSES = @(
    'explorer.exe', 'svchost.exe', 'lsass.exe', 'csrss.exe', 'wininit.exe',
    'services.exe', 'winlogon.exe', 'taskhostw.exe', 'spoolsv.exe', 'dwm.exe'
)

# Simulate DLL Search Order
function Get-DLLSearchPaths {
    param (
        [string]$ProcessPath,
        [string]$DLLName
    )
    $paths = @()
    $processDir = Split-Path -Parent $ProcessPath

    # 1. Application directory
    $paths += Join-Path $processDir $DLLName

    # 2. System32
    $paths += Join-Path $env:SystemRoot "System32\$DLLName"

    # 3. Windows Directory
    $paths += Join-Path $env:SystemRoot $DLLName

    # 4. Current directory
    $paths += Join-Path (Get-Location) $DLLName

    # 5. PATH environment variable directories
    $paths += ($env:Path -split ';' | ForEach-Object { Join-Path $_ $DLLName })

    return $paths
}

# Function to check DLL existence
function Test-DLLExists {
    param ([string]$DLLPath)
    return Test-Path $DLLPath
}

# Function to analyze a process
function Analyze-Process {
    param ([System.Diagnostics.Process]$Process)
    Write-Host "[INFO] Analyzing process: $($Process.ProcessName) (PID: $($Process.Id))" -ForegroundColor Cyan
    try {
        $processPath = $Process.MainModule.FileName
        $modules = $Process.Modules | Where-Object { $_.ModuleName -match '\.dll$' }

        $missingDLLs = @()

        foreach ($module in $modules) {
            try {
                $dllName = $module.ModuleName
                $dllPaths = Get-DLLSearchPaths -ProcessPath $processPath -DLLName $dllName

                # Check if the DLL exists in any search path
                $found = $dllPaths | Where-Object { Test-DLLExists -DLLPath $_ }
                if (-not $found) {
                    Write-Host "[MISSING] DLL Not Found: $dllName, Affected Executable: $($Process.MainModule.FileName)" -ForegroundColor Red
                    $missingDLLs += $dllName
                }
            } catch {
                Write-Host "[ERROR] Error analyzing module $($module.ModuleName): $_" -ForegroundColor Yellow
            }
        }

        return $missingDLLs
    } catch {
        Write-Host "[ERROR] Unable to analyze process: $($Process.ProcessName): $_" -ForegroundColor Red
        return @()
    }
}

# Main scanning function
function Start-DLLSideloadingScan {
    Write-Host "[INFO] Starting DLL sideloading vulnerability scan..." -ForegroundColor Green
    $results = @()

    # Enumerate all processes
    $processes = Get-Process | Where-Object { $_.MainModule -and $STANDARD_WINDOWS_PROCESSES -notcontains $_.ProcessName }
    foreach ($process in $processes) {
        $missingDLLs = Analyze-Process -Process $process
        if ($missingDLLs.Count -gt 0) {
            foreach ($dll in $missingDLLs) {
                $results += [PSCustomObject]@{
                    ProcessName = $process.ProcessName
                    ProcessId = $process.Id
                    ProcessPath = $process.MainModule.FileName
                    MissingDLL = $dll
                }
            }
        }
    }

    # Output results
    if ($results.Count -gt 0) {
        Write-Host "[INFO] Missing DLLs detected:" -ForegroundColor Yellow
        $results | ForEach-Object {
            Write-Host "DLL Not Found: $($_.MissingDLL), Affected Executable: $($_.ProcessPath)" -ForegroundColor Red
        }

        # CSV Export Option
        $exportChoice = Read-Host "Do you want to export results to CSV? (y/n)"
        if ($exportChoice -eq "y") {
            $scanTime = Get-Date -Format 'yyyyMMdd_HHmmss'
            $exportPath = Join-Path $env:USERPROFILE "Desktop\DLLSideloadingScan_$scanTime.csv"
            $results | Export-Csv -Path $exportPath -NoTypeInformation
            Write-Host "[INFO] Results exported to: $exportPath" -ForegroundColor Green
        }
    } else {
        Write-Host "[INFO] No missing DLLs detected." -ForegroundColor Green
    }
}

# Start the scan
Start-DLLSideloadingScan
