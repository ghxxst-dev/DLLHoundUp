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

# DLL Sideloading Scanner
# This script scans running processes and their loaded DLLs to identify potential DLL sideloading opportunities
# with additional filtering for high-probability targets

# Requires running with administrator privileges
#Requires -RunAsAdministrator

# Configuration
$VERY_SMALL_EXECUTABLE_SIZE = 50MB  # Maximum size for strict targeted scan
$SMALL_EXECUTABLE_SIZE = 100MB      # Maximum size for medium targeted scan
$STRICT_MAX_DLL_DEPENDENCIES = 10   # Maximum DLL dependencies for strict targeted scan
$MAX_DLL_DEPENDENCIES = 50          # Maximum DLL dependencies for medium targeted scan
$CUSTOM_MAX_SIZE = 0                # Will be set by user input
$CUSTOM_MAX_DLLS = 0                # Will be set by user input
$COMMON_SYSTEM_DLLS = @(
    'kernel32.dll', 'user32.dll', 'gdi32.dll', 'advapi32.dll', 'shell32.dll',
    'ole32.dll', 'oleaut32.dll', 'ntdll.dll', 'msvcrt.dll', 'ws2_32.dll'
)

# Function to check if a DLL exists in the specified path
function Test-DLLExists {
    param (
        [string]$DLLPath
    )
    return Test-Path $DLLPath
}

# Function to resolve potential DLL search paths
function Get-DLLSearchPaths {
    param (
        [string]$ProcessPath,
        [string]$DLLName
    )
    
    $searchPaths = @()
    
    # 1. Process directory
    $processDir = Split-Path -Parent $ProcessPath
    $searchPaths += Join-Path $processDir $DLLName
    
    # 2. System32 directory
    $searchPaths += Join-Path $env:SystemRoot "System32\$DLLName"
    
    # 3. Windows directory
    $searchPaths += Join-Path $env:SystemRoot $DLLName
    
    # 4. Current working directory (for completeness)
    $searchPaths += Join-Path (Get-Location) $DLLName
    
    return $searchPaths
}

# Function to check if a process is a likely target
function Test-IsLikelyTarget {
    param (
        [System.Diagnostics.Process]$Process,
        [switch]$StrictMode,
        [switch]$CustomMode,
        [int64]$CustomSize,
        [int]$CustomDLLs
    )
    
    try {
        # Check executable size
        $executableSize = (Get-Item $Process.MainModule.FileName).Length
        $maxSize = if ($CustomMode) { 
            $CustomSize 
        } elseif ($StrictMode) { 
            $VERY_SMALL_EXECUTABLE_SIZE 
        } else { 
            $SMALL_EXECUTABLE_SIZE 
        }
        
        if ($executableSize -gt $maxSize) {
            Write-Verbose "Process $($Process.ProcessName) excluded: size too large ($executableSize bytes)"
            return $false
        }

        # Check number of dependencies
        $dllCount = $Process.Modules.Count
        $maxDeps = if ($CustomMode) {
            $CustomDLLs
        } elseif ($StrictMode) {
            $STRICT_MAX_DLL_DEPENDENCIES
        } else {
            $MAX_DLL_DEPENDENCIES
        }
        
        if ($dllCount -gt $maxDeps) {
            Write-Verbose "Process $($Process.ProcessName) excluded: too many dependencies ($dllCount)"
            return $false
        }

        # Check if it's running from Program Files or other common install locations
        $processPath = $Process.MainModule.FileName
        if ($processPath -like "*\Windows\*" -or 
            $processPath -like "*\Microsoft.NET\*" -or 
            $processPath -like "*\WindowsApps\*") {
            Write-Verbose "Process $($Process.ProcessName) excluded: system location"
            return $false
        }

        # Count non-system DLLs
        $nonSystemDLLs = $Process.Modules | 
            Where-Object { $COMMON_SYSTEM_DLLS -notcontains $_.ModuleName.ToLower() }
        if ($nonSystemDLLs.Count -lt 2) {
            Write-Verbose "Process $($Process.ProcessName) excluded: only system DLLs"
            return $false
        }

        return $true
    }
    catch {
        Write-Verbose "Error checking process $($Process.ProcessName): $_"
        return $false
    }
}

# Main scanning function
function Start-DLLSideloadingScan {
    param (
        [ValidateSet("Full", "Medium", "Strict", "Custom")]
        [string]$ScanType = "Full",
        [int64]$CustomSize = 0,
        [int]$CustomDLLs = 0
    )

    # Initialize results array
    $results = @()

    Write-Host "Starting DLL sideloading vulnerability scan..." -ForegroundColor Green
    switch ($ScanType) {
        "Strict" {
            Write-Host "Running in strict targeted mode - focusing on small applications (<50MB, <10 DLLs)" -ForegroundColor Red
        }
        "Medium" {
            Write-Host "Running in medium targeted mode - focusing on medium-sized applications (<100MB, <50 DLLs)" -ForegroundColor Yellow
        }
        "Custom" {
            Write-Host "Running in custom mode - Max Size: $($CustomSize/1MB)MB, Max DLLs: $CustomDLLs" -ForegroundColor Magenta
        }
        "Full" {
            Write-Host "Running in full scan mode - scanning all applications" -ForegroundColor Green
        }
    }

    # Get all running processes
    $processes = Get-Process | Where-Object { $_.MainModule }

    foreach ($process in $processes) {
        try {
            if ($ScanType -ne "Full") {
                $customParams = @{
                    Process = $process
                    StrictMode = ($ScanType -eq "Strict")
                    CustomMode = ($ScanType -eq "Custom")
                }
                if ($ScanType -eq "Custom") {
                    $customParams['CustomSize'] = $CustomSize
                    $customParams['CustomDLLs'] = $CustomDLLs
                }
                $isLikelyTarget = Test-IsLikelyTarget @customParams
                if (-not $isLikelyTarget) {
                    continue
                }
            }

            Write-Host "Scanning process: $($process.ProcessName)" -ForegroundColor Yellow
            
            # Get process path
            $processPath = $process.MainModule.FileName
            
            # Get loaded modules (DLLs)
            $modules = $process.Modules
            
            foreach ($module in $modules) {
                try {
                    $dllName = $module.ModuleName
                    $dllPath = $module.FileName

                    # Skip common system DLLs in targeted mode
                    if ($TargetedScanOnly -and ($COMMON_SYSTEM_DLLS -contains $dllName.ToLower())) {
                        continue
                    }
                    
                    # Get potential search paths for this DLL
                    $searchPaths = Get-DLLSearchPaths -ProcessPath $processPath -DLLName $dllName
                    
                    # Check if any potential DLL paths are missing
                    foreach ($path in $searchPaths) {
                        if (-not (Test-DLLExists -DLLPath $path)) {
                            $results += [PSCustomObject]@{
                                ProcessName = $process.ProcessName
                                ProcessPath = $processPath
                                ProcessSize = (Get-Item $processPath).Length
                                DLLCount = $modules.Count
                                MissingDLL = $dllName
                                SearchedPath = $path
                                IsHighProbability = $TargetedScanOnly
                            }
                        }
                    }
                }
                catch {
                    Write-Host "Error processing module $($module.ModuleName): $_" -ForegroundColor Red
                    continue
                }
            }
        }
        catch {
            Write-Host "Error processing process $($process.ProcessName): $_" -ForegroundColor Red
            continue
        }
    }

    # Output results
    if ($results.Count -gt 0) {
        Write-Host "`nPotential DLL Sideloading Vulnerabilities Found:" -ForegroundColor Red
        
        if ($TargetedScanOnly) {
            Write-Host "Showing only high-probability targets matching criteria:" -ForegroundColor Yellow
            Write-Host "- Executable size < 100MB" -ForegroundColor Yellow
            Write-Host "- Less than 50 DLL dependencies" -ForegroundColor Yellow
            Write-Host "- Not running from system directories" -ForegroundColor Yellow
            Write-Host "- Has non-system DLL dependencies" -ForegroundColor Yellow
        }
        
        # Display simplified output in terminal
        Write-Host "`nVulnerable Programs:" -ForegroundColor Yellow
        $results | ForEach-Object {
            Write-Host "`nProgram: " -NoNewline -ForegroundColor Green
            Write-Host "$($_.ProcessName)"
            Write-Host "Path: " -NoNewline -ForegroundColor Green
            Write-Host "$($_.ProcessPath)"
            Write-Host "Missing DLL: " -NoNewline -ForegroundColor Green
            Write-Host "$($_.MissingDLL)"
            Write-Host "---"
        }
        
        # Export results to CSV
        $scanType = if ($TargetedScanOnly) { "Targeted" } else { "Full" }
        $exportPath = Join-Path $env:USERPROFILE "Desktop\DLLSideloadingScan_${scanType}_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $results | Export-Csv -Path $exportPath -NoTypeInformation
        Write-Host "`nResults exported to: $exportPath" -ForegroundColor Green
    }
    else {
        Write-Host "`nNo potential DLL sideloading vulnerabilities found." -ForegroundColor Green
    }
}

# Prompt user for scan type
Write-Host "`nSelect scan type:" -ForegroundColor Cyan
Write-Host "1: Full Scan (All Applications)" -ForegroundColor Green
Write-Host "2: Medium Scan (<100MB, <50 DLLs)" -ForegroundColor Yellow
Write-Host "3: Strict Scan (<50MB, <10 DLLs)" -ForegroundColor Red
Write-Host "4: Custom Scan (Define your own limits)" -ForegroundColor Magenta

$scanChoice = Read-Host "`nEnter scan type (1-4)"

switch ($scanChoice) {
    "1" { Start-DLLSideloadingScan -ScanType "Full" }
    "2" { Start-DLLSideloadingScan -ScanType "Medium" }
    "3" { Start-DLLSideloadingScan -ScanType "Strict" }
    "4" { 
        $customSize = Read-Host "Enter maximum executable size in MB (e.g., 75 for 75MB)"
        $customDLLs = Read-Host "Enter maximum number of DLL dependencies (e.g., 25)"
        
        # Convert MB to bytes
        $sizeInBytes = [int64]$customSize * 1MB
        
        Start-DLLSideloadingScan -ScanType "Custom" -CustomSize $sizeInBytes -CustomDLLs ([int]$customDLLs)
    }
    default { 
        Write-Host "Invalid choice. Running Full Scan." -ForegroundColor Yellow
        Start-DLLSideloadingScan -ScanType "Full" 
    }
}
