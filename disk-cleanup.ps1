# Disk Cleanup Script written by: Charlie Maddex (github.com/name/disk-cleanup)
param (
    [switch] $clean = $false
)

Function disk_space_status {
    $result = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq "3" } |
    Select-Object SystemName,
    @{ Name = "Drive" ; Expression = { ( $_.DeviceID ) } },
    @{ Name = "Size (GB)" ; Expression = { "{0:N1}" -f ( $_.Size / 1gb) } },
    @{ Name = "FreeSpace (GB)" ; Expression = { "{0:N1}" -f ( $_.Freespace / 1gb ) } },
    @{ Name = "PercentFree" ; Expression = { "{0:P1}" -f ( $_.FreeSpace / $_.Size ) } } |
    Format-Table -AutoSize |
    Out-String
    Return $result
}

Function get_large_files {
    $drive_list = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq "3" } | Select-Object DeviceID
    
    ForEach ($drive in $drive_list) {
        Write-Host "Scanning $($drive.DeviceID) for large files..."
        $scan_path = "$($drive.DeviceID)\"
        Write-Host ( Get-ChildItem $scan_path -Recurse -ErrorAction SilentlyContinue | 
            Where-Object { $_.Length -gt 1GB } | 
            Sort-Object Length -Descending | Select-Object Name, Directory,
            @{Name = "Size (GB)"; Expression = { "{0:N2}" -f ($_.Length / 1GB) } } | Format-List |
            Out-String )
    }
}

Function get_log_files {
    $drive_list = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq "3" } | Select-Object DeviceID
    
    ForEach ($drive in $drive_list) {
        Write-Host "Scanning $($drive.DeviceID) for log files..."
        $scan_path = "$($drive.DeviceID)\"
        Write-Host ( Get-ChildItem $scan_path -Recurse -ErrorAction SilentlyContinue | 
            Where-Object { $_.Length -gt 100MB -and $_.Extension -eq ".log" } | 
            Sort-Object Length -Descending | Select-Object Name, Directory,
            @{Name = "Size (MB)"; Expression = { "{0:N2}" -f ($_.Length / 1MB) } } | Format-List |
            Out-String )
    }
}

Function clean_log_files {
    $drive_list = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq "3" } | Select-Object DeviceID
    
    ForEach ($drive in $drive_list) {
        Write-Host "`nScanning $($drive.DeviceID) for log files..."
        $scan_path = "$($drive.DeviceID)\"
        $file_list = Get-ChildItem $scan_path -Recurse -ErrorAction SilentlyContinue | 
        Where-Object { $_.Length -gt 100MB -and $_.Extension -eq ".log" } | 
        Sort-Object Length -Descending

        ForEach ($file in $file_list) {
            if ($file.LastWriteTime -lt (Get-Date).AddDay(-7)) {
                Write-Host "Removing $($file.FullName)..."
                Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue -Confirm:$false
            }
        }
    }
}

Function check_root_folders {
    Write-Host "`nChecking root folders..."
    $root_folders = @(
        "C:\Program Files",
        "C:\Program Files (x86)",
        "C:\ProgramData",
        "C:\Users",
        "C:\Windows",
        "C:\`$Recycle.Bin",
        "C:\Documents and Settings",
        "C:\System Volume Information",
        "C:\`$WinREAgent",
        "C:\Config.Msi",
        "C:\OneDriveTemp",
        "C:\Recovery"
    )

    Get-ChildItem -Path "C:\" -Directory -Force -ErrorAction SilentlyContinue |
    Where-Object { $root_folders -notcontains $_.FullName } | ForEach-Object {
        $folder = $_.FullName
        $folder_size = Get-ChildItem -Path $folder -Recurse -Force -ErrorAction SilentlyContinue |
        Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty Sum
        $folder_size = "{0:N1}" -f ( $folder_size / 1gb )
        $folder_size = [math]::Round($folder_size, 1)
        $folder_size = $folder_size.ToString() + " GB"
        $folder = $folder + " (" + $folder_size + ")"
        $folder
    } | Out-String
}

Function clean_software_distribution {
    Write-Host "Cleaning SoftwareDistribution folder..."
    $service = Get-Service -Name wuauserv
    if ($service.Status -eq "Running") {
        Stop-Service -Name wuauserv
    }
    $folder_path = "C:\Windows\SoftwareDistribution"
    $folder_size = Get-ChildItem -Path $folder_path -Recurse -Force -ErrorAction SilentlyContinue |
    Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty Sum
    $folder_size = "{0:N1}" -f ( $folder_size / 1gb )
    $folder_size = [math]::Round($folder_size, 1)
    $folder_size = $folder_size.ToString() + " GB"
    $folder = $folder_path + " (" + $folder_size + ")"
    $folder
    Remove-Item -Path $folder_path -Recurse -Force -ErrorAction SilentlyContinue -Confirm:$false
    if ($service.Status -eq "Stopped") {
        Start-Service -Name wuauserv
    }
}

Function clean_catroot {
    Write-Host "`nCleaning catroot folder..."
    $service = Get-Service -Name wuauserv
    if ($service.Status -eq "Running") {
        Stop-Service -Name wuauserv
    }
    $folder_path = "C:\Windows\System32\catroot"
    $folder_size = Get-ChildItem -Path $folder_path -Recurse -Force -ErrorAction SilentlyContinue |
    Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty Sum
    $folder_size = "{0:N1}" -f ( $folder_size / 1gb )
    $folder_size = [math]::Round($folder_size, 1)
    $folder_size = $folder_size.ToString() + " GB"
    $folder = $folder_path + " (" + $folder_size + ")"
    $folder
    Remove-Item -Path $folder_path -Recurse -Force -ErrorAction SilentlyContinue
    if ($service.Status -eq "Stopped") {
        Start-Service -Name wuauserv
    }
}

Function clean_temp_files {
    Write-Host "`nCleaning temp files..."
    $clean_folders = @(
        "C:\Windows\Temp",
        "C:\inetpub\logs\LogFiles",
        "C:\Users\*\AppData\Local\Temp",
        "C:\Users\*\AppData\Local\Microsoft\Windows\Temporary Internet Files",
        "C:\Users\*\AppData\Local\Microsoft\Windows\WER",
        "C:\Users\*\AppData\Local\Microsoft\Terminal Server Client\Cache"
    )

    ForEach ($folder_path in $clean_folders) {
        $folder_size = Get-ChildItem -Path $folder_path -Recurse -Force -ErrorAction SilentlyContinue |
        Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty Sum
        $folder_size = "{0:N1}" -f ( $folder_size / 1gb )
        $folder_size = [math]::Round($folder_size, 1)
        $folder_size = $folder_size.ToString() + " GB"
        $folder = $folder_path + " (" + $folder_size + ")"
        $folder
        
        $file_list = Get-ChildItem -Path $folder_path -Recurse -Force -ErrorAction SilentlyContinue

        ForEach ($file in $file_list) {
            if ($file.LastWriteTime -lt (Get-Date).AddHours(-12)) {
                Write-Host "Removing $($file.FullName)"
                Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue -Confirm:$false
            }
        }
    }
}

Write-Host "`nDisk Cleanup Script written by: Charlie Maddex (github.com/name/disk-cleanup)"
Write-Host "Host: $(Hostname), PowerShell Version: $($PSVersionTable.PSVersion.Major)`n"

# Check that the user is running as Administrator
$windows_identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$windows_principal = New-Object System.Security.Principal.WindowsPrincipal($windows_identity)
$admin_role = [System.Security.Principal.WindowsBuiltInRole]::Administrator
if (-not ($windows_principal.IsInRole($admin_role))) {
    Write-Host "You must run this script as an Administrator, launching a new instance..."
    # Start the same script as an Administrator
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

# Check that the user is running PowerShell 3.0 or higher
if ($PSVersionTable.PSVersion.Major -lt 3) {
    Write-Host "You are running a PowerShell version under 3.0, some features may not work as exected.`n" -ForegroundColor Red
}
$disk_space_before = disk_space_status

if ($clean -eq $false) {
    Write-Host "Generating Disk Cleanup Report..."
    Write-Host $disk_space_before
    check_root_folders
    get_large_files
    get_log_files
    Write-Host "`nDisk Cleanup Report Complete!"
}
else {
    Write-Host "Running Disk Cleanup..."
    Write-Host $disk_space_before

    Clear-RecycleBin -DriveLetter C -Force -Verbose -ErrorAction SilentlyContinue
    clean_software_distribution
    clean_catroot
    clean_temp_files
    clean_log_files
    check_root_folders
    get_large_files
    
    Write-Host "`nDisk Cleanup Complete!"
    $disk_space_after = disk_space_status
    Write-Host $disk_space_after
}
