# DLLHound - DLL Sideloading Scanner
# Author: @ajm4n
# Description: Scans processes for potential DLL sideloading vulnerabilities

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

$COMMON_SYSTEM_DLLS = @(
    'kernel32.dll', 'user32.dll', 'gdi32.dll', 'advapi32.dll', 'shell32.dll',
    'ole32.dll', 'oleaut32.dll', 'ntdll.dll', 'msvcrt.dll', 'ws2_32.dll'
)

# Function to get imported DLLs from PE header
function Get-ImportedDLLs {
    param (
        [string]$FilePath
    )
    try {
        Write-Host "Reading PE header from: $FilePath" -ForegroundColor DarkGray
        
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
        $signature = [BitConverter]::ToUInt32($bytes, $peOffset)
        
        if ($signature -ne 0x4550) { # "PE\0\0"
            Write-Host "Invalid PE signature found" -ForegroundColor Yellow
            return @()
        }
        
        $optionalHeaderOffset = $peOffset + 24
        $importDirRvaOffset = $optionalHeaderOffset + 104
        $importDirRva = [BitConverter]::ToInt32($bytes, $importDirRvaOffset)
        $dllImports = @()
        $sectionOffset = $optionalHeaderOffset + 240

        for ($i = 0; $i -lt 16; $i++) {
            $sectionStart = $sectionOffset + ($i * 40)
            if ($sectionStart + 40 -gt $bytes.Length) { break }
            
            $virtualAddress = [BitConverter]::ToInt32($bytes, $sectionStart + 12)
            $rawAddress = [BitConverter]::ToInt32($bytes, $sectionStart + 20)
            
            if ($importDirRva -ge $virtualAddress -and 
                $importDirRva -lt ($virtualAddress + [BitConverter]::ToInt32($bytes, $sectionStart + 8))) {
                
                $fileOffset = ($importDirRva - $virtualAddress) + $rawAddress
                
                while ($fileOffset -lt $bytes.Length - 20) {
                    $nameRva = [BitConverter]::ToInt32($bytes, $fileOffset + 12)
                    if ($nameRva -eq 0) { break }
                    
                    $nameOffset = ($nameRva - $virtualAddress) + $rawAddress
                    $dllName = ""
                    $currentOffset = $nameOffset
                    
                    while ($currentOffset -lt $bytes.Length) {
                        $byte = $bytes[$currentOffset]
                        if ($byte -eq 0) { break }
                        $dllName += [char]$byte
                        $currentOffset++
                    }
                    
                    if ($dllName -match '\.dll$') {
                        Write-Host "Found imported DLL: $dllName" -ForegroundColor DarkGray
                        $dllImports += $dllName
                    }
                    
                    $fileOffset += 20 # Size of import descriptor
                }
                break
            }
        }
        
        return $dllImports | Select-Object -Unique
    }
    catch {
        Write-Host "Error analyzing PE file: $_" -ForegroundColor Red
        return @()
    }
}

# Function to check DLL load paths
function Get-DLLSearchOrder {
    param (
        [string]$ProcessPath,
        [string]$DLLName
    )
    
    $searchPaths = @()
    $processDir = Split-Path -Parent $ProcessPath
    
    # Windows DLL Search Order
    $searchPaths += @{
        Priority = 1
        Path = Join-Path $processDir $DLLName
        Description = "Application Directory"
    }
    
    $searchPaths += @{
        Priority = 2
        Path = Join-Path $env:SystemRoot "System32\$DLLName"
        Description = "System32 Directory"
    }
    
    $searchPaths += @{
        Priority = 3
        Path = Join-Path $env:SystemRoot "System\$DLLName"
        Description = "16-bit System Directory"
    }
    
    $searchPaths += @{
        Priority = 4
        Path = Join-Path $env:SystemRoot $DLLName
        Description = "Windows Directory"
    }
    
    $searchPaths += @{
        Priority = 5
        Path = Join-Path (Get-Location) $DLLName
        Description = "Current Directory"
    }
    
    # PATH environment variable directories
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

# Function to check if a process is a likely target
function Test-IsLikelyTarget {
    param (
        [System.Diagnostics.Process]$Process,
        [switch]$StrictMode,
        [switch]$CustomMode,
        [int64]$CustomSize = 0,
        [int]$CustomDLLs = 0
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
            return $false
        }

        # Check if it's running from system locations
        $processPath = $Process.MainModule.FileName
        if ($processPath -like '*\Windows\*' -or 
            $processPath -like '*\Microsoft.NET\*' -or 
            $processPath -like '*\WindowsApps\*') {
            return $false
        }

        return $true
    }
    catch {
        Write-Host "Error checking process $($Process.ProcessName): $_" -ForegroundColor Red
        return $false
    }
}
# Main scanning function
function Start-DLLSideloadingScan {
    [CmdletBinding()]
    param (
        [ValidateSet("Full", "Medium", "Strict", "Custom")]
        [string]$ScanType = "Full",
        [int64]$CustomSize = 0,
        [int]$CustomDLLs = 0
    )

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
            
            $processPath = $process.MainModule.FileName
            Write-Host "Process path: $processPath" -ForegroundColor DarkGray
            
            Write-Host "Analyzing PE imports..." -ForegroundColor DarkGray
            $importedDLLs = Get-ImportedDLLs -FilePath $processPath
            
            Write-Host "Getting loaded modules..." -ForegroundColor DarkGray
            $loadedDLLs = $process.Modules | Where-Object {
                $_.ModuleName.EndsWith('.dll', [StringComparison]::OrdinalIgnoreCase)
            } | Select-Object -ExpandProperty ModuleName
            
            Write-Host "Found $($importedDLLs.Count) imported DLLs, $($loadedDLLs.Count) loaded DLLs" -ForegroundColor DarkGray
            
            $missingDLLs = $importedDLLs | Where-Object { $loadedDLLs -notcontains $_ }
            
            foreach ($dllName in $missingDLLs) {
                try {
                    if ($ScanType -ne "Full" -and ($COMMON_SYSTEM_DLLS -contains $dllName.ToLower())) {
                        Write-Host "Skipping system DLL: $dllName" -ForegroundColor DarkGray
                        continue
                    }
                    
                    Write-Host "`nChecking missing DLL: $dllName" -ForegroundColor Yellow
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
        catch {
            Write-Host "Error processing process $($process.ProcessName): $_" -ForegroundColor Red
            continue
        }
    }

    # Output results
    if ($results.Count -gt 0) {
        # Filter out .exe files from results for display
        $nonExeResults = $results | Where-Object { $_.ProcessPath -notlike '*.exe' }
        
        if ($nonExeResults.Count -gt 0) {
            Write-Host "`nVulnerable Programs:" -ForegroundColor Yellow
            $nonExeResults | ForEach-Object {
                Write-Host "`nProgram: " -NoNewline -ForegroundColor Green
                Write-Host $_.ProcessName
                Write-Host "Path: " -NoNewline -ForegroundColor Green
                Write-Host $_.ProcessPath
                Write-Host "Missing DLL: " -NoNewline -ForegroundColor Green
                Write-Host $_.MissingDLL
                Write-Host "Search Path: " -NoNewline -ForegroundColor Green
                Write-Host $_.SearchPath
                Write-Host "Search Priority: " -NoNewline -ForegroundColor Green
                Write-Host $_.SearchPriority
                Write-Host "---"
            }
            
            # Export results to CSV
            $scanTime = Get-Date -Format 'yyyyMMdd_HHmmss'
            $exportPath = Join-Path $env:USERPROFILE "Desktop\DLLSideloadingScan_$($ScanType)_$($scanTime).csv"
            $nonExeResults | Export-Csv -Path $exportPath -NoTypeInformation
            Write-Host "`nResults exported to: $exportPath" -ForegroundColor Green
            Write-Host ("Found {0} DLL issues in non-executable files." -f $nonExeResults.Count) -ForegroundColor Yellow
        }
        else {
        Write-Host "`nNo DLL issues found in non-executable files." -ForegroundColor Yellow
        }
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
