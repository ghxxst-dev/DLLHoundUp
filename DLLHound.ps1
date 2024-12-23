# Enhanced DLL Sideloading Scanner

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
    if (![string]::IsNullOrWhiteSpace($processDir)) {
        $paths += Join-Path $processDir $DLLName
    }

    # 2. Custom search paths
    $CustomSearchPaths | ForEach-Object {
        if (![string]::IsNullOrWhiteSpace($_)) {
            $paths += Join-Path $_ $DLLName
        }
    }

    # 3. System32
    $paths += Join-Path $env:SystemRoot "System32\$DLLName"

    # 4. Windows Directory
    $paths += Join-Path $env:SystemRoot $DLLName

    # 5. Current directory
    $paths += Join-Path (Get-Location) $DLLName

    # 6. PATH environment variable directories
    $paths += ($env:Path -split ';' | ForEach-Object {
        if (![string]::IsNullOrWhiteSpace($_)) {
            Join-Path $_ $DLLName
        }
    })

    # Filter out invalid or empty paths
    return $paths | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
}

# Function to check DLL existence
function Test-DLLExists {
    param ([string]$DLLPath)
    try {
        if ([string]::IsNullOrWhiteSpace($DLLPath)) {
            Write-Host "[DEBUG] Received an empty or invalid DLL path." -ForegroundColor Yellow
            return $false
        }

        # Debugging Log
        Write-Host "[DEBUG] Checking DLL Path: $DLLPath" -ForegroundColor DarkGray

        return [System.IO.File]::Exists($DLLPath)
    } catch {
        Write-Host "[ERROR] Unable to check DLL existence: $DLLPath - $_" -ForegroundColor Red
        return $false
    }
}

# Function to analyze a process
function Analyze-Process {
    param (
        [System.Diagnostics.Process]$Process
    )
    Write-Host "[INFO] Analyzing process: $($Process.ProcessName) (PID: $($Process.Id))" -ForegroundColor Cyan
    try {
        $processPath = $Process.MainModule.FileName
        $modules = $Process.Modules | Where-Object { $_.ModuleName -match '\.dll$' }
        $missingDLLs = @()

        foreach ($module in $modules) {
            try {
                $dllName = $module.ModuleName
                $dllPaths = Get-DLLSearchPaths -ProcessPath $processPath -DLLName $dllName

                # Debugging Log: Log all generated paths
                Write-Host "[DEBUG] DLL Search Paths for `${dllName}`:" -ForegroundColor DarkGray
                foreach ($path in $dllPaths) {
                    Write-Host "  $path" -ForegroundColor DarkGray
                }

                # Filter out empty or invalid paths before testing
                $validPaths = $dllPaths | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

                # Check if the DLL exists in any search path
                $found = $validPaths | Where-Object { Test-DLLExists $_ }
                if (-not $found) {
                    Write-Host "[MISSING] DLL Not Found: `${dllName}`, Affected Executable: ${processPath}" -ForegroundColor Red
                    $missingDLLs += $dllName
                }
            } catch {
                Write-Host "[ERROR] Error analyzing module `${dllName}`: $_" -ForegroundColor Yellow
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

# Start the scan
Start-DLLSideloadingScan
