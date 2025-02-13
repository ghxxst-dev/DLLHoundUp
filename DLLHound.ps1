#Requires -RunAsAdministrator

$script:VerboseOutput = $false

Write-Host @"
______ _      _      _   _                       _ _   _       
|  _  \ |    | |    | | | |                     | | | | |      
| | | | |    | |    | |_| | ___  _   _ _ __   __| | | | |_ __  
| | | | |    | |    |  _  |/ _ \| | | | '_ \ / _` | | | | '_ \ 
| |/ /| |____| |____| | | | (_) | |_| | | | | (_| | |_| | |_) |
|___/ \_____/\_____/\_| |_/\___/ \__,_|_| |_|\__,_|\___/| .__/ 
                                                        | |    
                                                        |_|    
                 by @ajm4n, forked for priv esc by @ghxxst-dev
"@ -ForegroundColor Cyan

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
    
    if ($Type -eq "VERBOSE" -and -not $script:VerboseOutput) {
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

function Test-UnprivilegedPath {
    param(
        [string]$Path
    )
    try {
        $directory = Split-Path -Path $Path -Parent
        if (-not (Test-Path $directory -PathType Container)) {
            return $false
        }

        $acl = Get-Acl $directory
        foreach ($ace in $acl.Access) {
            if (
                ($ace.IdentityReference -match 'Everyone|BUILTIN\\Users') -and
                ($ace.FileSystemRights.ToString() -match 'Write|FullControl|Modify') -and
                ($ace.AccessControlType -eq 'Allow')
            ) {
                return $true
            }
        }
    } catch {
        return $false
    }
    return $false
}

function Test-HighPrivilegeProcess {
    param(
        [System.Diagnostics.Process]$Process
    )
    try {
        $cimProc    = Get-CimInstance Win32_Process -Filter "ProcessId=$($Process.Id)"
        $ownerInfo  = $cimProc | Invoke-CimMethod -MethodName "GetOwner"
        $ownerSid   = $cimProc | Invoke-CimMethod -MethodName "GetOwnerSid"

        if ($ownerInfo) {
            $fullUser = "$($ownerInfo.Domain)\$($ownerInfo.User)"

            if ($fullUser -in @("NT AUTHORITY\SYSTEM",
                                "NT AUTHORITY\LOCAL SERVICE",
                                "NT AUTHORITY\NETWORK SERVICE")) {
                return $true
            }

            if ($ownerSid) {
                $windowsIdentity  = New-Object System.Security.Principal.WindowsIdentity($ownerSid.Sid)
                $windowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($windowsIdentity)
                if ($windowsPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
                    return $true
                }
            }
        }
    } catch {
        return $false
    }
    return $false
}

function Get-DllSearchPaths {
    param(
        [string]$ProcessPath,
        [string]$DllName
    )
    
    $searchPaths = @()
    $processDir = Split-Path -Parent $ProcessPath
    
    if ($processDir) {
        $searchPaths += Join-Path $processDir $DllName
    }
    
    foreach ($path in $script:CustomSearchPaths) {
        $searchPaths += Join-Path $path $DllName
    }
    
    $searchPaths += Join-Path $env:SystemRoot "System32\$DllName"
    $searchPaths += Join-Path $env:SystemRoot $DllName
    
    $searchPaths += Join-Path (Get-Location) $DllName
    
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
    Write-LogMessage "Analyzing process: $($Process.ProcessName) (PID: $($Process.Id))" -Type "VERBOSE" -Color DarkGray
    
    $isHighPrivilege = Test-HighPrivilegeProcess -Process $Process
    if (-not $isHighPrivilege) {
        return $results
    }

    try {
        $processPath = $Process.MainModule.FileName
        $modules = $Process.Modules | Where-Object { $_.ModuleName -match '\.dll$' }
        
        foreach ($module in $modules) {
            try {
                $dllName = $module.ModuleName
                $searchPaths = Get-DllSearchPaths -ProcessPath $processPath -DllName $dllName
                
                if ($script:VerboseOutput) {
                    Write-LogMessage "Checking paths for $dllName" -Type "VERBOSE" -Color DarkGray
                    $searchPaths | ForEach-Object { 
                        Write-LogMessage "  $_" -Type "VERBOSE" -Color DarkGray 
                    }
                }

                $found = $false
                $unprivPathUsed = $false

                foreach ($path in $searchPaths) {
                    if (Test-Path $path -ErrorAction SilentlyContinue) {
                        $found = $true
                        break
                    } else {
                        if (Test-UnprivilegedPath -Path $path) {
                            $unprivPathUsed = $true
                        }
                    }
                }

                if (-not $found -and $unprivPathUsed) {
                    Write-LogMessage "POTENTIAL Vulnerability: $dllName not found - Process: $($Process.ProcessName), unprivileged path in search order." -Type "MISSING" -Color Red
                    $results += [PSCustomObject]@{
                        ProcessName   = $Process.ProcessName
                        ProcessId     = $Process.Id
                        ProcessPath   = $processPath
                        MissingDLL    = $dllName
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
    Write-LogMessage "Starting DLL sideloading vulnerability scan (High-Priv [incl. Local Admin] + Unprivileged Path)..." -Type "INFO" -Color Green
    
    $verboseChoice = Read-Host "Enable verbose mode? (y/n)"
    $script:VerboseOutput = $verboseChoice -eq 'y'
    
    if ($script:VerboseOutput) {
        Write-LogMessage "Verbose mode enabled" -Type "INFO" -Color Yellow
    }
    
    Write-Host "`nEnter custom search paths (press Enter without input to continue):"
    while ($true) {
        $path = Read-Host "Enter path"
        if ([string]::IsNullOrWhiteSpace($path)) { break }
        Add-CustomSearchPath $path
    }
    
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
    
    if ($results.Count -gt 0) {
        Write-LogMessage "Found $($results.Count) potential DLL sideloading privesc vulnerabilities:" -Type "INFO" -Color Green
        $results | Select-Object MissingDLL, ProcessPath | Format-Table -AutoSize -Wrap
        
        $exportChoice = Read-Host "Export results to CSV? (y/n)"
        if ($exportChoice -eq 'y') {
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $desktopLocation = [Environment]::GetFolderPath("Desktop")
            $csvPath = Join-Path $desktopLocation "DLLScan_$timestamp.csv"
            $results | Export-Csv -Path $csvPath -NoTypeInformation
            Write-LogMessage "Results exported to: $csvPath" -Type "INFO" -Color Green
        }
    } else {
        Write-LogMessage "No DLL sideloading vulnerabilities that allow privilege escalation detected (under current definitions)." -Type "INFO" -Color Green
    }
}

Start-DLLScan
