# Requires running with administrator privileges
#Requires -RunAsAdministrator

# Global debug flag
$script:ShowDebug = $false

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

function Write-LogMessage {
    param(
        [string]$Message,
        [string]$Type = "INFO",
        [ConsoleColor]$Color = "White"
    )
    
    if ($Type -eq "DEBUG" -and -not $script:ShowDebug) {
        return
    }
    
    Write-Host "[$Type] $Message" -ForegroundColor $Color
}

function Add-CustomSearchPath {
    param([string]$Path)
    if (Test-Path $Path) {
        $script:CustomSearchPaths += $Path
        Write-LogMessage "Added custom search path: $Path" -Type "INFO" -Color Green
    } else {
        Write-LogMessage "Invalid path: $Path" -Type "ERROR" -Color Red
    }
}

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

function Analyze-Process {
    param([System.Diagnostics.Process]$Process)
    
    $results = @()
    Write-LogMessage "Analyzing process: $($Process.ProcessName) (PID: $($Process.Id))" -Type "DEBUG" -Color DarkGray
    
    try {
        $processPath = $Process.MainModule.FileName
        $modules = $Process.Modules | Where-Object { $_.ModuleName -match '\.dll$' }
        
        foreach ($module in $modules) {
            try {
                $dllName = $module.ModuleName
                $searchPaths = Get-DllSearchPaths -ProcessPath $processPath -DllName $dllName
                
                if ($script:ShowDebug) {
                    Write-LogMessage "Checking paths for $dllName" -Type "DEBUG" -Color DarkGray
                    $searchPaths | ForEach-Object { 
                        Write-LogMessage "  $_" -Type "DEBUG" -Color DarkGray 
                    }
                }
                
                $found = $false
                foreach ($path in $searchPaths) {
                    if (Test-Path $path -ErrorAction SilentlyContinue) {
                        $found = $true
                        break
                    }
                }
                
                if (-not $found) {
                    Write-LogMessage "DLL Not Found: $dllName (Process: $($Process.ProcessName))" -Type "MISSING" -Color Red
                    $results += [PSCustomObject]@{
                        ProcessName = $Process.ProcessName
                        ProcessId = $Process.Id
                        ProcessPath = $processPath
                        MissingDLL = $dllName
                        SearchedPaths = $searchPaths -join ';'
                    }
                }
            } catch {
                Write-LogMessage "Error analyzing module $($module.ModuleName): $($_.Exception.Message)" -Type "ERROR" -Color Yellow
            }
        }
    } catch {
        Write-LogMessage "Error accessing process $($Process.ProcessName): $($_.Exception.Message)" -Type "ERROR" -Color Red
    }
    
    return $results
}

function Start-DLLScan {
    Write-LogMessage "Starting DLL sideloading vulnerability scan..." -Type "INFO" -Color Green
    
    # Enable/Disable Debug Mode
    $debugChoice = Read-Host "Enable debug mode? (y/n)"
    $script:ShowDebug = $debugChoice -eq 'y'
    
    if ($script:ShowDebug) {
        Write-LogMessage "Debug mode enabled" -Type "INFO" -Color Yellow
    }
    
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
        Write-LogMessage "Found $($results.Count) potential DLL sideloading vulnerabilities:" -Type "INFO" -Color Green
        $results | Format-Table -AutoSize
        
        # Export option
        $exportChoice = Read-Host "Export results to CSV? (y/n)"
        if ($exportChoice -eq 'y') {
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $csvPath = Join-Path $env:USERPROFILE "Desktop\DLLScan_$timestamp.csv"
            $results | Export-Csv -Path $csvPath -NoTypeInformation
            Write-LogMessage "Results exported to: $csvPath" -Type "INFO" -Color Green
        }
    } else {
        Write-LogMessage "No DLL sideloading vulnerabilities detected." -Type "INFO" -Color Green
    }
}

# Start the scan
Start-DLLScan
