# Disk Cleanup Script

This script is used to clean up the disk space on a Windows machine. This is compatible with Windows 10+, Windows Server 2012 R2+, and limited support for Windows Server 2008 R2.

## Usage

The script can be run in two ways:

1. **Report Mode** - This mode will run the script and output a report of useful information to help with manual cleanup.
2. **Cleanup Mode** - This mode will run the script and perform the cleanup automatically.

## How to Run

You can run the script by opening an Administrative PowerShell window and running the following command depending on the mode you want to run:

```powershell
# Requires PowerShell 3.0+

## Report Mode
iex (iwr 'https://raw.githubusercontent.com/name/disk-cleanup/main/disk-cleanup.ps1')

## Cleanup Mode
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/name/disk-cleanup/main/disk-cleanup.ps1' -OutFile 'disk-cleanup.ps1' -Force ; & '.\disk-cleanup.ps1' -clean
```

## Examples

### Report Mode

[Screenshot](https://raw.githubusercontent.com/name/disk-cleanup/main/images/report-mode.png)

### Cleanup Mode

[Screenshot](https://raw.githubusercontent.com/name/disk-cleanup/main/images/cleanup-mode.png)
