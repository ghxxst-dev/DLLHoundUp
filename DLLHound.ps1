# Requires running with administrator privileges
#Requires -RunAsAdministrator

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [switch]$Debug,
    
    [Parameter(Mandatory = $false)]
    [string[]]$CustomPaths,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath,
    
    [Parameter(Mandatory = $false)]
    [switch]$ExportCsv
)

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

# Logging functions
function Write-DebugLog {
    param([string]$Message)
    if ($Debug) {
        Write-Host "[DEBUG] $Message" -ForegroundColor DarkGray
    }
}

function Write-InfoLog {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Green
}

function Write-WarningLog {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-ErrorLog {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Write-MissingLog {
    param([string]$Message)
    Write-Host "[MISSING] $Message" -ForegroundColor Red
}

# Get DLL search paths
function Get-DllSearchPaths {
    param (
        [string]$ProcessPath,
        [string]$DllName
    )
    
    $paths = [System.Collections.ArrayList]::new()
    $processDir = Split-Path -Parent $ProcessPath
    
    if (![string]::IsNullOrWhiteSpace($processDir)) {
        $null = $paths.Add((Join-Path $processDir $DllName))
    }
    
    foreach ($path in $CustomPaths) {
        if (![string]::IsNullOrWhiteSpace($path)) {
            $null = $paths.Add((Join-Path $path $DllName))
        }
    }
    
    $null = $paths.Add((Join-Path $env:SystemRoot "System32\$DllName"))
    $null = $paths.Add((Join-Path $env:SystemRoot $DllName))
    $null = $paths.Add((Join-Path (Get-Location) $DllName))
    
    foreach ($path in ($env:Path -split ';')) {
        if (![string]::IsNullOrWhiteSpace($path)) {
            $null = $paths.Add((Join-Path $path $DllName))
        }
    }
    
    return $paths.ToArray()
}

# Test if DLL exists
function Test-DllExists {
    param([string]$DllPath)
    
    try {
        if ([string]::IsNullOrWhiteSpace($DllPath)) {
            Write-DebugLog "Received empty or invalid DLL path."
            return $false
        }
        
        Write-DebugLog "Checking DLL Path: $DllPath"
        return [System.IO.File]::Exists($DllPath)
    }
    catch {
        Write-ErrorLog "Unable to check DLL existence: $DllPath - $($_.Exception.Message)"
        return $false
    }
}

# Analyze a single process
function Analyze-Process {
    param([System.Diagnostics.Process]$Process)
    
    Write-DebugLog "Analyzing process: $($Process.ProcessName) (PID: $($Process.Id))"
    $results = [System.Collections.ArrayList]::new()
    
    try {
        $processPath = $Process.MainModule.FileName
        $modules = $Process.Modules | Where-Object { $_.ModuleName -match '\.dll$' }
        
        foreach ($module in $modules) {
            try {
                $dllName = $module.ModuleName
                $dllPaths = Get-DllSearchPaths -ProcessPath $processPath -DllName $dllName
                
                if ($Debug) {
                    Write-DebugLog "DLL Search Paths for $dllName"
                    $dllPaths | ForEach-Object { Write-DebugLog "  $_" }
                }
                
                $found = $false
                foreach ($path in $dllPaths) {
                    if (Test-DllExists -DllPath $path) {
                        $found = $true
                        break
                    }
                }
                
                if (-not $found) {
                    Write-MissingLog "DLL Not Found: $dllName, Affected Executable: $processPath"
                    $null = $results.Add([PSCustomObject]@{
                        ProcessName = $Process.ProcessName
                        ProcessId = $Process.Id
                        ProcessPath = $processPath
                        MissingDLL = $dllName
                        SearchedPaths = $dllPaths
                    })
                }
            }
            catch {
                Write-WarningLog "Error analyzing module $dllName`: $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-ErrorLog "Unable to analyze process $($Process.ProcessName): $($_.Exception.Message)"
    }
    
    return $results.ToArray()
}

# Main scanning function
function Start-DllSideloadingScan {
    Write-InfoLog "Starting DLL sideloading vulnerability scan..."
    
    if ($Debug) {
        Write-DebugLog "Debug Mode is ENABLED. Verbose output will be displayed."
    }
    
    $results = [System.Collections.ArrayList]::new()
    $processes = Get-Process | Where-Object { 
        $_.MainModule -and $STANDARD_WINDOWS_PROCESSES -notcontains $_.ProcessName 
    }
    
    foreach ($process in $processes) {
        $processResults = Analyze-Process -Process $process
        if ($processResults.Count -gt 0) {
            $null = $results.AddRange($processResults)
        }
    }
    
    if ($results.Count -gt 0) {
        Write-InfoLog "Missing DLLs detected:"
        $results | Format-Table -Property ProcessName, ProcessId, MissingDLL, ProcessPath -AutoSize
        
        if ($ExportCsv) {
            $csvPath = $OutputPath
            if ([string]::IsNullOrWhiteSpace($csvPath)) {
                $scanTime = Get-Date -Format 'yyyyMMdd_HHmmss'
                $csvPath = Join-Path $env:USERPROFILE "Desktop\DLLSideloadingScan_$scanTime.csv"
            }
            $results | Export-Csv -Path $csvPath -NoTypeInformation
            Write-InfoLog "Results exported to: $csvPath"
        }
    }
    else {
        Write-InfoLog "No missing DLLs detected."
    }
}

# Start the scan
Start-DllSideloadingScan
