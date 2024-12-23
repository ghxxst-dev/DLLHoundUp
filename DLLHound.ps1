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
class ScanConfig {
    [string[]]$CommonSystemDlls = @(
        'kernel32.dll', 'user32.dll', 'gdi32.dll', 'advapi32.dll', 'shell32.dll',
        'ole32.dll', 'oleaut32.dll', 'ntdll.dll', 'msvcrt.dll', 'ws2_32.dll'
    )
    
    [string[]]$StandardWindowsProcesses = @(
        'explorer.exe', 'svchost.exe', 'lsass.exe', 'csrss.exe', 'wininit.exe',
        'services.exe', 'winlogon.exe', 'taskhostw.exe', 'spoolsv.exe', 'dwm.exe'
    )
    
    [string[]]$CustomSearchPaths
    [bool]$DebugMode
    
    ScanConfig([bool]$debug, [string[]]$customPaths) {
        $this.DebugMode = $debug
        $this.CustomSearchPaths = $customPaths
    }
}

# Create logger class for consistent logging
class Logger {
    static [void] Debug([string]$message, [bool]$debugMode) {
        if ($debugMode) {
            Write-Host "[DEBUG] $message" -ForegroundColor DarkGray
        }
    }
    
    static [void] Info([string]$message) {
        Write-Host "[INFO] $message" -ForegroundColor Green
    }
    
    static [void] Warning([string]$message) {
        Write-Host "[WARNING] $message" -ForegroundColor Yellow
    }
    
    static [void] Error([string]$message) {
        Write-Host "[ERROR] $message" -ForegroundColor Red
    }
    
    static [void] Missing([string]$message) {
        Write-Host "[MISSING] $message" -ForegroundColor Red
    }
}

class DllScanner {
    [ScanConfig]$Config
    
    DllScanner([ScanConfig]$config) {
        $this.Config = $config
    }
    
    [string[]] GetDllSearchPaths([string]$processPath, [string]$dllName) {
        $paths = [System.Collections.ArrayList]::new()
        $processDir = Split-Path -Parent $processPath
        
        # 1. Application directory
        if (![string]::IsNullOrWhiteSpace($processDir)) {
            $paths.Add((Join-Path $processDir $dllName)) | Out-Null
        }
        
        # 2. Custom search paths
        foreach ($path in $this.Config.CustomSearchPaths) {
            if (![string]::IsNullOrWhiteSpace($path)) {
                $paths.Add((Join-Path $path $dllName)) | Out-Null
            }
        }
        
        # 3. System directories
        $paths.Add((Join-Path $env:SystemRoot "System32\$dllName")) | Out-Null
        $paths.Add((Join-Path $env:SystemRoot $dllName)) | Out-Null
        $paths.Add((Join-Path (Get-Location) $dllName)) | Out-Null
        
        # 4. PATH environment variable directories
        foreach ($path in ($env:Path -split ';')) {
            if (![string]::IsNullOrWhiteSpace($path)) {
                $paths.Add((Join-Path $path $dllName)) | Out-Null
            }
        }
        
        return $paths.ToArray()
    }
    
    [bool] TestDllExists([string]$dllPath) {
        try {
            if ([string]::IsNullOrWhiteSpace($dllPath)) {
                [Logger]::Debug("Received empty or invalid DLL path.", $this.Config.DebugMode)
                return $false
            }
            
            [Logger]::Debug("Checking DLL Path: $dllPath", $this.Config.DebugMode)
            return [System.IO.File]::Exists($dllPath)
        }
        catch {
            [Logger]::Error("Unable to check DLL existence: $dllPath - $_")
            return $false
        }
    }
    
    [PSCustomObject[]] AnalyzeProcess([System.Diagnostics.Process]$process) {
        [Logger]::Debug("Analyzing process: $($process.ProcessName) (PID: $($process.Id))", $this.Config.DebugMode)
        $results = [System.Collections.ArrayList]::new()
        
        try {
            $processPath = $process.MainModule.FileName
            $modules = $process.Modules | Where-Object { $_.ModuleName -match '\.dll$' }
            
            foreach ($module in $modules) {
                try {
                    $dllName = $module.ModuleName
                    $dllPaths = $this.GetDllSearchPaths($processPath, $dllName)
                    
                    if ($this.Config.DebugMode) {
                        [Logger]::Debug("DLL Search Paths for ${dllName}:", $true)
                        $dllPaths | ForEach-Object { [Logger]::Debug("  $_", $true) }
                    }
                    
                    $found = $false
                    foreach ($path in $dllPaths) {
                        if ($this.TestDllExists($path)) {
                            $found = $true
                            break
                        }
                    }
                    
                    if (-not $found) {
                        [Logger]::Missing("DLL Not Found: ${dllName}, Affected Executable: ${processPath}")
                        $results.Add([PSCustomObject]@{
                            ProcessName = $process.ProcessName
                            ProcessId = $process.Id
                            ProcessPath = $processPath
                            MissingDLL = $dllName
                            SearchedPaths = $dllPaths
                        }) | Out-Null
                    }
                }
                catch {
                    [Logger]::Warning("Error analyzing module ${dllName}: $_")
                }
            }
        }
        catch {
            [Logger]::Error("Unable to analyze process: $($process.ProcessName): $_")
        }
        
        return $results.ToArray()
    }
    
    [void] StartScan([string]$outputPath, [bool]$exportCsv) {
        [Logger]::Info("Starting DLL sideloading vulnerability scan...")
        
        if ($this.Config.DebugMode) {
            [Logger]::Debug("Debug Mode is ENABLED. Verbose output will be displayed.", $true)
        }
        
        $results = [System.Collections.ArrayList]::new()
        $processes = Get-Process | Where-Object { 
            $_.MainModule -and $this.Config.StandardWindowsProcesses -notcontains $_.ProcessName 
        }
        
        foreach ($process in $processes) {
            $processResults = $this.AnalyzeProcess($process)
            if ($processResults.Count -gt 0) {
                $results.AddRange($processResults)
            }
        }
        
        if ($results.Count -gt 0) {
            [Logger]::Info("Missing DLLs detected:")
            $results | Format-Table -Property ProcessName, ProcessId, MissingDLL, ProcessPath -AutoSize
            
            if ($exportCsv) {
                $csvPath = $outputPath
                if ([string]::IsNullOrWhiteSpace($csvPath)) {
                    $scanTime = Get-Date -Format 'yyyyMMdd_HHmmss'
                    $csvPath = Join-Path $env:USERPROFILE "Desktop\DLLSideloadingScan_$scanTime.csv"
                }
                $results | Export-Csv -Path $csvPath -NoTypeInformation
                [Logger]::Info("Results exported to: $csvPath")
            }
        }
        else {
            [Logger]::Info("No missing DLLs detected.")
        }
    }
}

# Main execution
$config = [ScanConfig]::new($Debug, $CustomPaths)
$scanner = [DllScanner]::new($config)
$scanner.StartScan($OutputPath, $ExportCsv)
