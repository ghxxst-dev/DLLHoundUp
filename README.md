# DLLHound
DLL Sideloading Scanner 🔧

Welcome to the DLLHound! This PowerShell script scans processes on your Windows system to identify missing or unresolved DLLs, helping you detect potential sideloading vulnerabilities. Inspired by the functionality of tools like Spartacus, this script works dynamically and does not require external tools like ProcMon.

Features 🚀

🔢 Dynamic Process Analysis

Scans running processes and their loaded DLLs.

Detects missing or unresolved DLLs dynamically.

📊 Detailed Reporting

Displays results in a structured table format.

Includes affected executable paths and missing DLL names.

🔧 Customizable Search Order

Simulates Windows DLL search order to locate libraries.

Skips common system DLLs and standard Windows processes.

📄 CSV Export

Export results for further analysis with a single command.

🔖 Real-Time Scanning

Dynamically analyzes processes as they run.

Requirements 🔐

Windows Operating System

Designed for Windows systems only.

Administrator Privileges

Required to access process and module details.

PowerShell 5.1 or later

Ensure your PowerShell version is up-to-date.

Installation 📚

Clone or download this repository.

Open PowerShell as Administrator.

Navigate to the script’s directory.

Usage ⚡

Run the script with:

.\DLLSideloadingScanner.ps1

Select the desired scan type:

Full Scan: Analyze all running processes.

Medium Scan: Focus on processes with smaller executable sizes (<100MB).

Strict Scan: Target processes with tiny executables (<50MB).

Custom Scan: Define your own size and dependency limits.

View results directly in the terminal.

Optionally export results to a CSV file:

Enter y when prompted to save the results.

Example Output 🔎

Terminal Table Format:

ProcessName    ProcessId MissingDLL         ProcessPath
-----------    --------- -----------        -----------
example.exe        1234 missing.dll        C:\Path\To\example.exe
example2.exe       5678 anothermissing.dll C:\Path\To\example2.exe

CSV Export:

The CSV file contains the following columns:

ProcessName

ProcessId

MissingDLL

ProcessPath

Saved to your Desktop automatically upon selection.

How It Works 🦜

Enumerates all running processes.

Extracts the executable path and dynamically loaded DLLs.

Simulates the Windows DLL search order to verify each DLL.

Identifies missing DLLs and associates them with their respective processes.

Outputs results in a clear, human-readable format or saves them to a CSV file.

Known Limitations ❗

Requires Administrator Privileges to access all processes.

Cannot analyze processes without valid main modules (e.g., system-protected processes).

Designed specifically for Windows systems.

Contributing 🙏

We welcome contributions! Feel free to fork this repository, create pull requests, or open issues for feature suggestions and bug reports.

License 🔒

This project is licensed under the MIT License.

Happy Scanning! 🚀

