
# Requires running with administrator privileges
#Requires -RunAsAdministrator

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
$COMMON_SYSTEM_DLLS = @(
    'kernel32.dll', 'user32.dll', 'gdi32.dll', 'advapi32.dll', 'shell32.dll',
    'ole32.dll', 'oleaut32.dll', 'ntdll.dll', 'msvcrt.dll', 'ws2_32.dll'
)
$STANDARD_WINDOWS_PROCESSES = @(
    'explorer.exe', 'svchost.exe', 'lsass.exe', 'csrss.exe', 'wininit.exe',
    'services.exe', 'winlogon.exe', 'taskhostw.exe', 'spoolsv.exe', 'dwm.exe'
)

# Customizable Search Paths
$CustomSearchPaths = @()

# Add Custom Search Paths
function Add-CustomSearchPath {
    param ([string]$Path)
    if (Test-Path $Path) {
        $CustomSearchPaths += $Path
        Write-Host "[INFO] Added custom search path: $Path" -ForegroundColor Green
    } else {
        Write-Host "[ERROR] Invalid path: $Path" -ForegroundColor Red
    }
}

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

    # 2. Custom search paths
    $CustomSearchPaths | ForEach-Object { $paths += Join-Path $_ $DLLName }

    # 3. System32
    $paths += Join-Path $env:SystemRoot "System32\$DLLName"

    # 4. Windows Directory
    $paths += Join-Path $env:SystemRoot $DLLName

    # 5. Current directory
    $paths += Join-Path (Get-Location) $DLLName

    # 6. PATH environment variable directories
    $paths += ($env:Path -split ';' | ForEach-Object { Join-Path $_ $DLLName })

    return $paths
}

# Function to open affected executable
function Open-ExecutablePath {
    param ([string]$ExecutablePath)
    if (Test-Path $ExecutablePath) {
        Write-Host "[INFO] Opening directory for: $ExecutablePath" -ForegroundColor Cyan
        Invoke-Item (Split-Path -Parent $ExecutablePath)
    } else {
        Write-Host "[ERROR] Cannot open directory. File does not exist: $ExecutablePath" -ForegroundColor Red
    }
}

# Function to analyze a process
function Analyze-Process {
    param (
        [System.Diagnostics.Process]$Process,
        [int64]$MaxSize = 0,
        [int]$MaxDLLs = 0,
        [switch]$CustomMode
    )
    Write-Host "[INFO] Analyzing process: $($Process.ProcessName) (PID: $($Process.Id))" -ForegroundColor Cyan
    try {
        $processPath = $Process.MainModule.FileName
        $size = (Get-Item $processPath).Length
        $dllCount = $Process.Modules.Count

        # Custom size and dependency filtering
        if ($CustomMode) {
            if ($MaxSize -gt 0 -and $size -gt ($MaxSize * 1MB)) {
                Write-Host "[SKIP] Process exceeds size limit ($size bytes > $($MaxSize * 1MB) bytes)." -ForegroundColor Yellow
                return @()
            }
            if ($MaxDLLs -gt 0 -and $dllCount -gt $MaxDLLs) {
                Write-Host "[SKIP] Process exceeds DLL dependency limit ($dllCount > $MaxDLLs)." -ForegroundColor Yellow
                return @()
            }
        }

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
    param (
        [switch]$CustomMode,
        [int64]$MaxSize = 0,
        [int]$MaxDLLs = 0
    )

    Write-Host "[INFO] Starting DLL sideloading vulnerability scan..." -ForegroundColor Green
    if ($CustomMode) {
        Write-Host "[INFO] Custom Mode Enabled: Max Size = $MaxSize MB, Max DLLs = $MaxDLLs" -ForegroundColor Cyan
    }

    $results = @()
    $processes = Get-Process | Where-Object { $_.MainModule -and $STANDARD_WINDOWS_PROCESSES -notcontains $_.ProcessName }
    foreach ($process in $processes) {
        $missingDLLs = Analyze-Process -Process $process -MaxSize $MaxSize -MaxDLLs $MaxDLLs -CustomMode:$CustomMode
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

    # Output results in table format
    if ($results.Count -gt 0) {
        Write-Host "[INFO] Missing DLLs detected:" -ForegroundColor Yellow
        $results | Format-Table -Property ProcessName, ProcessId, MissingDLL, ProcessPath -AutoSize

        # CSV Export Option
        $exportChoice = Read-Host "Do you want to export results to CSV? (y/n)"
        if ($exportChoice -eq "y") {
            $scanTime = Get-Date -Format 'yyyyMMdd_HHmmss'
            $exportPath = Join-Path $env:USERPROFILE "Desktop\DLLSideloadingScan_$scanTime.csv"
            $results | Export-Csv -Path $exportPath -NoTypeInformation
            Write-Host "[INFO] Results exported to: $exportPath" -ForegroundColor Green
        }

        # Open Executable Option
        $openChoice = Read-Host "Do you want to open the directory of an affected executable? Enter the process name or 'n' to skip."
        if ($openChoice -ne 'n') {
            $selectedProcess = $results | Where-Object { $_.ProcessName -eq $openChoice }
            if ($selectedProcess) {
                Open-ExecutablePath -ExecutablePath $selectedProcess.ProcessPath
            } else {
                Write-Host "[ERROR] Process not found in the results." -ForegroundColor Red
            }
        }
    } else {
        Write-Host "[INFO] No missing DLLs detected." -ForegroundColor Green
    }
}

# Add Custom Search Paths Option
Write-Host "Do you want to add custom DLL search paths? (Enter paths or 'n' to skip)" -ForegroundColor Cyan
while ($true) {
    $customPath = Read-Host "Enter a custom search path (or 'done' to finish)"
    if ($customPath -eq 'n' -or $customPath -eq 'done') { break }
    Add-CustomSearchPath -Path $customPath
}

# Prompt for Custom Scan
$enableCustomScan = Read-Host "Do you want to enable a custom scan? (y/n)"
if ($enableCustomScan -eq "y") {
    $maxSize = [int64](Read-Host "Enter maximum executable size in MB (e.g., 100 for 100MB)")
    $maxDLLs = [int](Read-Host "Enter maximum number of DLL dependencies (e.g., 50)")
    Start-DLLSideloadingScan -CustomMode -MaxSize $maxSize -MaxDLLs $maxDLLs
} else {
    Start-DLLSideloadingScan
}
