# DLLHound - DLL Sideloading Scanner
# This script scans running processes and their loaded DLLs to identify potential DLL sideloading opportunities
# with additional filtering for high-probability targets and custom scan options

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
$VERY_SMALL_EXECUTABLE_SIZE = 50MB  # Maximum size for strict targeted scan
$SMALL_EXECUTABLE_SIZE = 100MB      # Maximum size for medium targeted scan
$STRICT_MAX_DLL_DEPENDENCIES = 10   # Maximum DLL dependencies for strict targeted scan
$MAX_DLL_DEPENDENCIES = 50          # Maximum DLL dependencies for medium targeted scan
$CUSTOM_MAX_SIZE = 0                # Will be set by user input for custom scan
$CUSTOM_MAX_DLLS = 0                # Will be set by user input for custom scan

$COMMON_SYSTEM_DLLS = @(
    'kernel32.dll', 'user32.dll', 'gdi32.dll', 'advapi32.dll', 'shell32.dll',
    'ole32.dll', 'oleaut32.dll', 'ntdll.dll', 'msvcrt.dll', 'ws2_32.dll'
)

# Function to check DLL load paths
function Get-DLLSearchOrder {
    param (
        [string]$ProcessPath,
        [string]$DLLName
    )
    
    $searchPaths = @()
    $processDir = Split-Path -Parent $ProcessPath
    
    # Windows DLL Search Order:
    # 1. The directory from which the application loaded
    $searchPaths += @{
        Priority = 1
        Path = Join-Path $processDir $DLLName
        Description = "Application Directory"
    }
    
    # 2. System directory (System32)
    $searchPaths += @{
        Priority = 2
        Path = Join-Path $env:SystemRoot "System32\$DLLName"
        Description = "System32 Directory"
    }
    
    # 3. 16-bit system directory (System)
    $searchPaths += @{
        Priority = 3
        Path = Join-Path $env:SystemRoot "System\$DLLName"
        Description = "16-bit System Directory"
    }
    
    # 4. Windows directory
    $searchPaths += @{
        Priority = 4
        Path = Join-Path $env:SystemRoot $DLLName
        Description = "Windows Directory"
    }
    
    # 5. Current working directory
    $searchPaths += @{
        Priority = 5
        Path = Join-Path (Get-Location) $DLLName
        Description = "Current Directory"
    }
    
    # 6. PATH environment variable directories
    $envPaths = $env:PATH -split ';'
    $priority = 6
    foreach ($path in $envPaths) {
        if (![string]::IsNullOrWhiteSpace($path)) {
            $searchPaths += @{
                Priority = $priority
                Path = Join-Path $path $DLLName
                Description = "PATH: $path"
            }
            $priority++
        }
    }
    
    return $searchPaths
}

# Function to get imported DLLs from PE header
function Get-ImportedDLLs {
    param (
        [string]$FilePath
    )
    try {
        $dllImports = @()
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        
        # Parse PE header to find imported DLLs
        # This is a basic implementation - in practice you'd want to properly parse the PE format
        $offset = 0
        while ($offset -lt $bytes.Length - 2) {
            # Look for .dll in the bytes
            if ($bytes[$offset] -eq 0x2E -and  # .
                $bytes[$offset + 1] -eq 0x64 -and  # d
                $bytes[$offset + 2] -eq 0x6C -and  # l
                $bytes[$offset + 3] -eq 0x6C) {  # l
                
                # Go backwards to find start of string
                $start = $offset
                while ($start -gt 0 -and $bytes[$start - 1] -ne 0) {
                    $start--
                }
                
                # Convert bytes to string
                $dllName = [System.Text.Encoding]::ASCII.GetString($bytes[$start..($offset + 3)])
                if ($dllName -match '^[a-zA-Z0-9_\-]+\.dll

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

            Write-Host "`nAnalyzing process: $($process.ProcessName) (PID: $($process.Id))" -ForegroundColor Cyan
            
            # Get process path and DLL information
            $processPath = $process.MainModule.FileName
            Write-Host "Process path: $processPath" -ForegroundColor DarkGray
            
            # Get list of imported DLLs from PE header
            Write-Host "Analyzing PE imports..." -ForegroundColor DarkGray
            $importedDLLs = Get-ImportedDLLs -FilePath $processPath
            
            # Get list of actually loaded DLLs
            Write-Host "Getting loaded modules..." -ForegroundColor DarkGray
            $loadedDLLs = $process.Modules | Where-Object {
                $_.ModuleName.EndsWith('.dll', [StringComparison]::OrdinalIgnoreCase)
            } | Select-Object -ExpandProperty ModuleName
            
            Write-Host "Found $($importedDLLs.Count) imported DLLs, $($loadedDLLs.Count) loaded DLLs" -ForegroundColor DarkGray
            
            # Find missing DLLs (imported but not loaded)
            $missingDLLs = $importedDLLs | Where-Object { $loadedDLLs -notcontains $_ }
            
            foreach ($dllName in $missingDLLs) {
                try {
                    # Skip common system DLLs in targeted modes
                    if ($ScanType -ne "Full" -and ($COMMON_SYSTEM_DLLS -contains $dllName.ToLower())) {
                        Write-Host "Skipping system DLL: $dllName" -ForegroundColor DarkGray
                        continue
                    }
                    
                    Write-Host "`nChecking missing DLL: $dllName" -ForegroundColor Yellow
                    
                    # Get all possible load paths
                    $searchPaths = Get-DLLSearchOrder -ProcessPath $processPath -DLLName $dllName
                    
                    foreach ($searchPath in $searchPaths) {
                        Write-Host "Checking path [$($searchPath.Priority)]: $($searchPath.Path)" -ForegroundColor DarkGray
                        
                        if (Test-Path $searchPath.Path) {
                            Write-Host "  Found at: $($searchPath.Path)" -ForegroundColor DarkGray
                        } else {
                            Write-Host "  Not found - potential DLL hijacking point" -ForegroundColor Red
                            
                            $results += [PSCustomObject]@{
                                ProcessName = $process.ProcessName
                                ProcessId = $process.Id
                                ProcessPath = $processPath
                                ProcessSize = (Get-Item $processPath).Length
                                DLLCount = $loadedDLLs.Count
                                MissingDLL = $dllName
                                SearchPath = $searchPath.Path
                                SearchPriority = $searchPath.Priority
                                SearchLocation = $searchPath.Description
                                ImportedDLLCount = $importedDLLs.Count
                                LoadedDLLCount = $loadedDLLs.Count
                                ScanType = $ScanType
                            }
                        }
                    }
                }
                catch {
                    Write-Host "Error processing DLL $dllName`: $_" -ForegroundColor Red
                    continue
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
        $scanTime = Get-Date -Format 'yyyyMMdd_HHmmss'
        $exportPath = Join-Path $env:USERPROFILE "Desktop\DLLSideloadingScan_${ScanType}_${scanTime}.csv"
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
) {
                    $dllImports += $dllName
                }
            }
            $offset++
        }
        
        return $dllImports | Select-Object -Unique
    }
    catch {
        Write-Verbose "Error reading PE imports: $_"
        return @()
    }
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

                    # Skip if not a DLL
                    if (-not $dllName.EndsWith('.dll', [StringComparison]::OrdinalIgnoreCase)) {
                        continue
                    }

                    # Skip common system DLLs in targeted modes
                    if ($ScanType -ne "Full" -and ($COMMON_SYSTEM_DLLS -contains $dllName.ToLower())) {
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
                                ScanType = $ScanType
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
        $scanTime = Get-Date -Format 'yyyyMMdd_HHmmss'
        $exportPath = Join-Path $env:USERPROFILE "Desktop\DLLSideloadingScan_${ScanType}_${scanTime}.csv"
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
