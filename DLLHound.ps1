# Requires running with administrator privileges
#Requires -RunAsAdministrator

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [switch]$Debug
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
$script:CommonSystemDlls = @(
    'kernel32.dll', 'user32.dll', 'gdi32.dll', 'advapi32.dll', 'shell32.dll',
    'ole32.dll', 'oleaut32.dll', 'ntdll.dll', 'msvcrt.dll', 'ws2_32.dll'
)

$script:StandardWindowsProcesses = @(
    'explorer.exe', 'svchost.exe', 'lsass.exe', 'csrss.exe', 'wininit.exe',
    'services.exe', 'winlogon.exe', 'taskhostw.exe', 'spoolsv.exe', 'dwm.exe'
)

$script:CustomSearchPaths = @()

# Logging functions
function Write-DebugMessage {
    param([string]$Message)
    if ($Debug) {
        Write-Host "[DEBUG] $Message" -ForegroundColor DarkGray
    }
}

function Write-InfoMessage {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Green
}

function Write-ErrorMessage {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Write-MissingMessage {
    param([string]$Message)
    Write-Host "[MISSING] $Message" -ForegroundColor Red
}

# Add custom search paths
function Add-CustomSearchPath {
    param([string]$Path)
    
    if (Test-Path $Path) {
        $script:CustomSearchPaths += $Path
        Write-InfoMessage "Added custom search path: $Path"
    } else {
        Write-ErrorMessage "Invalid path: $Path"
    }
}

# Get DLL search paths
function Get-DllSearchPaths {
    param(
        [string]$ProcessPath,
        [string]$DllName
    )
    
    $searchPaths = @()
    $processDir = Split-Path -Parent $ProcessPath
    
    # 1. Process directory
    if ($processDir) {
        $searchPaths += Join-Path $processDir $DllName
    }
    
    # 2. Custom search paths
    foreach ($path in $script:CustomSearchPaths) {
        $searchPaths += Join-Path $path $DllName
    }
    
    # 3. System directories
    $searchPaths += Join-Path $env:SystemRoot "System32\$DllName"
    $searchPaths += Join-Path $env:SystemRoot $DllName
    
    # 4. Current directory
    $searchPaths += Join-Path (Get-Location) $DllName
    
    # 5. PATH directories
    $env:Path -split ';' | ForEach-Object {
        if ($_) {
            $searchPaths += Join-Path $_ $DllName
        }
    }
    
    return $searchPaths
}

# Process analysis function
function Analyze-Process {
    param([System.Diagnostics.Process]$Process)
    
    $results = @()
    Write-DebugMessage "Analyzing process: $($Process.ProcessName) (PID: $($Process.Id))"
    
    try {
        $processPath = $Process.MainModule.FileName
        $modules = $Process.Modules | Where-Object { $_.ModuleName -match '\.dll$' }
        
        foreach ($module in $modules) {
            try {
                $dllName = $module.ModuleName
                $searchPaths = Get-DllSearchPaths -ProcessPath $processPath -DllName $dllName
                
                if ($Debug) {
                    Write-DebugMessage "Checking paths for $dllName"
                    $searchPaths | ForEach-Object { Write-DebugMessage "  $_" }
                }
                
                $found = $false
                foreach ($path in $searchPaths) {
                    if (Test-Path $path -ErrorAction SilentlyContinue) {
                        $found = $true
                        break
                    }
                }
                
                if (-not $found) {
                    Write-MissingMessage "DLL Not Found: $dllName (Process: $($Process.ProcessName))"
                    $results += [PSCustomObject]@{
                        ProcessName = $Process.ProcessName
                        ProcessId = $Process.Id
                        ProcessPath = $processPath
                        MissingDLL = $dllName
                        SearchedPaths = $searchPaths -join ';'
                    }
                }
            } catch {
                Write-ErrorMessage "Error analyzing module $($module.ModuleName): $($_.Exception.Message)"
            }
        }
    } catch {
        Write-ErrorMessage "Error accessing process $($Process.ProcessName): $($_.Exception.Message)"
    }
    
    return $results
}

# Main scanning function
function Start-DLLScan {
    Write-InfoMessage "Starting DLL sideloading vulnerability scan..."
    
    # Get custom search paths
    Write-Host "`nEnter custom search paths (press Enter without input to continue):"
    while ($true) {
        $path = Read-Host "Enter path"
        if ([string]::IsNullOrWhiteSpace($path)) { break }
        Add-CustomSearchPath $path
    }
    
    # Scan processes
    $results = @()
    $processes = Get-Process | Where-Object { 
        $_.MainModule -and ($script:StandardWindowsProcesses -notcontains $_.ProcessName) 
    }
    
    foreach ($process in $processes) {
        $processResults = Analyze-Process -Process $process
        if ($processResults) {
            $results += $processResults
        }
    }
    
    # Display results
    if ($results.Count -gt 0) {
        Write-InfoMessage "Found $($results.Count) potential DLL sideloading vulnerabilities:"
        $results | Format-Table -AutoSize
        
        # Export option
        $exportChoice = Read-Host "Export results to CSV? (y/n)"
        if ($exportChoice -eq 'y') {
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $csvPath = Join-Path $env:USERPROFILE "Desktop\DLLScan_$timestamp.csv"
            $results | Export-Csv -Path $csvPath -NoTypeInformation
            Write-InfoMessage "Results exported to: $csvPath"
        }
    } else {
        Write-InfoMessage "No DLL sideloading vulnerabilities detected."
    }
}

# Start the scan
Start-DLLScan
