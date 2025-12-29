<#
.SYNOPSIS
    Capture and restore user data for migration purposes, including browsers, Wi-Fi, VPN, signatures, mapped drives, printers, and Sticky Notes.

.DESCRIPTION
    This script allows administrators to capture a user’s environment to a ZIP file (optionally encrypted)
    and restore it later on the same or another machine. It supports selective capture of data components.

.PARAMETER Mode
    Specifies whether to capture or restore data. Valid values: 'Capture', 'Restore'.

.PARAMETER Path
    Path to save the ZIP file (for Capture) or to read from (for Restore).

.PARAMETER Encrypt
    Optional switch to encrypt the ZIP file using AES-256. Requires -Password.

.PARAMETER Password
    Password to encrypt or decrypt the ZIP file. Required if -Encrypt is specified.

.PARAMETER Include
    Optional array of components to capture. Valid values include:
    "Browsers","WiFi","VPN","Signatures","MappedDrives","Printers","StickyNotes".
    If not specified, all components are captured.

.EXAMPLE
    # Capture all user data to C:\Backup\UserData.zip
    .\PSUserMigrate.ps1 -Mode Capture -Path "C:\Backup\UserData.zip"

.EXAMPLE
    # Capture only browsers and Wi-Fi with encryption
    .\PSUserMigrate.ps1 -Mode Capture -Path "C:\Backup\UserData.zip" -Encrypt -Password "P@ssw0rd" -Include Browsers,WiFi

.EXAMPLE
    # Restore data from an encrypted ZIP
    .\PSUserMigrate.ps1 -Mode Restore -Path "C:\Backup\UserData.zip" -Encrypt -Password "P@ssw0rd"

.NOTES
    Requires PowerShell 5.1 or higher.
    Some operations may require administrative privileges (VPN, mapped drives, printers).
    Ensure 7-Zip is installed or will be installed via winget if encryption is used.
#>

param (
    [Parameter(Mandatory)]
    [ValidateSet("Capture","Restore")]
    [string]$Mode,

    [Parameter(Mandatory)]
    [string]$Path,             # Path to save/read ZIP (not the same as $env:Path)

    [switch]$Encrypt,
    [securestring]$Password,         # Required if -Encrypt

    [string[]]$Include         # Optional: selective capture (e.g., "Browsers","WiFi","VPN","Signatures","MappedDrives","Printers","StickyNotes")
)

$ErrorActionPreference = "Stop"
$ErrorLog = "$env:TEMP\UserMigrationErrors.log"
if (Test-Path $ErrorLog) { Remove-Item $ErrorLog }

# Function: Ensure 7-Zip Installed
function Test-7Zip {
    param (
        [string]$Path = "C:\Program Files\7-Zip\7z.exe"
    )
    if (Test-Path $Path) { return $Path }

    Write-Host "7-Zip not found. Installing via winget..." -ForegroundColor Yellow

    if (Get-Command winget -ErrorAction SilentlyContinue) {
        try {
            winget install --id=7zip.7zip -e --silent
            $attempts = 0
            while (-not (Test-Path $Path) -and $attempts -lt 10) {
                Start-Sleep -Seconds 5
                $attempts++
            }
        } catch {
            $msg = "Failed to install 7-Zip via winget: $_"
            Write-Error $msg
            Add-Content -Path $ErrorLog -Value $msg
            throw $msg
        }
        if (-not (Test-Path $Path)) {
            $msg = "7-Zip not found after installation. Manual install required."
            Write-Error $msg
            Add-Content -Path $ErrorLog -Value $msg
            throw $msg
        }
        Write-Host "7-Zip installed successfully." -ForegroundColor Green
        return $Path
    } else {
        $msg = "winget not found. Please install 7-Zip manually."
        Write-Error $msg
        Add-Content -Path $ErrorLog -Value $msg
        throw $msg
    }
}

# Validation
if ($Encrypt -and -not $Password) {
    $msg = "Encryption requested but no password supplied."
    Write-Error $msg
    Add-Content -Path $ErrorLog -Value $msg
    throw $msg
}

if ($Encrypt) {
    $SevenZip = Test-7Zip
}

# Capture Function
function Backup-UserData {
    param (
        [string]$ZipPath,
        [string[]]$IncludeItems
    )

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $user = $env:USERNAME
    $computer = $env:COMPUTERNAME
    $workingRoot = Join-Path $env:TEMP "UserMigration-$user-$timestamp"
    try {
        New-Item -ItemType Directory -Path $workingRoot -Force | Out-Null
    } catch {
        $msg = "Failed to create working directory ${workingRoot}: $_"
        Write-Error $msg
        Add-Content -Path $ErrorLog -Value $msg
        throw $msg
    }

    if (-not $IncludeItems) {
        $IncludeItems = @("Browsers","WiFi","VPN","Signatures","MappedDrives","Printers","StickyNotes")
    }

    # Browsers
    if ($IncludeItems -contains "Browsers") {
        Write-Host "Capturing browser data..." -ForegroundColor Cyan
        $browserPaths = @{
            "Chrome"  = "$env:LOCALAPPDATA\Google\Chrome\User Data"
            "Edge"    = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
            "Firefox" = "$env:APPDATA\Mozilla\Firefox"
            "Opera"   = "$env:APPDATA\Opera Software"
        }
        foreach ($browser in $browserPaths.Keys) {
            if (Test-Path $browserPaths[$browser]) {
                try {
                    Copy-Item $browserPaths[$browser] -Destination "$workingRoot\$browser" -Recurse -Force -ErrorAction Stop
                    Write-Host "$browser captured successfully." -ForegroundColor Green
                } catch {
                    $msg = "Failed to capture ${browser}: $_"
                    Write-Warning $msg
                    Add-Content -Path $ErrorLog -Value $msg
                }
            }
        }
    }

    # Wi-Fi (client-only)
    $wifiProfiles = @()
    try {
        $os = Get-CimInstance Win32_OperatingSystem
    } catch {
        $msg = "Failed to detect OS type: $_"
        Write-Warning $msg
        Add-Content -Path $ErrorLog -Value $msg
        $os = $null
    }

    if ($IncludeItems -contains "WiFi" -and $os -and $os.ProductType -eq 1) {
        Write-Host "Capturing Wi-Fi profiles..." -ForegroundColor Cyan
        $wifiDir = Join-Path $workingRoot "WiFi"
        try { New-Item -ItemType Directory -Path $wifiDir -Force | Out-Null } catch {}
        try {
            $profiles = netsh wlan show profiles |
                Select-String "All User Profile" |
                ForEach-Object { ($_ -split ":")[1].Trim() }
            foreach ($userProfile in $profiles) {
                try { netsh wlan export profile name="$userProfile" key=clear folder="$wifiDir" | Out-Null } catch {
                    $msg = "Failed to export Wi-Fi profile ${userProfile}: $_"
                    Write-Warning $msg
                    Add-Content -Path $ErrorLog -Value $msg
                }
            }
            $wifiProfiles = $profiles
        } catch {
            $msg = "Failed to retrieve Wi-Fi profiles: $_"
            Write-Warning $msg
            Add-Content -Path $ErrorLog -Value $msg
        }
    }

    # VPN
    if ($IncludeItems -contains "VPN") {
        Write-Host "Capturing VPN settings..." -ForegroundColor Cyan
        $vpnDir = Join-Path $workingRoot "VPN"
        try { New-Item -ItemType Directory -Path $vpnDir -Force | Out-Null } catch {}
        try {
            Get-VpnConnection -AllUserConnection | Export-Clixml "$vpnDir\WindowsVPN.xml"
        } catch {
            $msg = "Failed to export Windows VPN connections: $_"
            Write-Warning $msg
            Add-Content -Path $ErrorLog -Value $msg
        }

        $openVpnPaths = @("$env:USERPROFILE\OpenVPN\config","C:\Program Files\OpenVPN\config")
        foreach ($path in $openVpnPaths) {
            if (Test-Path $path) {
                try { Copy-Item $path -Destination "$vpnDir\OpenVPN" -Recurse -Force -ErrorAction Stop } catch {
                    $msg = "Failed to copy OpenVPN configs from ${path}: $_"
                    Write-Warning $msg
                    Add-Content -Path $ErrorLog -Value $msg
                }
            }
        }
    }

    # Outlook Signatures
    if ($IncludeItems -contains "Signatures") {
        $sigPath = "$env:APPDATA\Microsoft\Signatures"
        if (Test-Path $sigPath) {
            Write-Host "Capturing Outlook signatures..." -ForegroundColor Cyan
            try { Copy-Item $sigPath "$workingRoot\OutlookSignatures" -Recurse -Force -ErrorAction Stop } catch {
                $msg = "Failed to capture Outlook signatures: $_"
                Write-Warning $msg
                Add-Content -Path $ErrorLog -Value $msg
            }
        }
    }

    # Mapped Drives
    if ($IncludeItems -contains "MappedDrives") {
        Write-Host "Capturing mapped drives..." -ForegroundColor Cyan
        try {
            $mappedDrives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -like "\\*" -and $null -eq $_.DisplayRoot }
            $mappedDrives | Export-Clixml "$workingRoot\MappedDrives.xml"
        } catch {
            $msg = "Failed to capture mapped drives: $_"
            Write-Warning $msg
            Add-Content -Path $ErrorLog -Value $msg
        }
    }

    # Printers
    if ($IncludeItems -contains "Printers") {
        Write-Host "Capturing printers..." -ForegroundColor Cyan
        try {
            $printers = Get-Printer | Where-Object { $_.Policy -eq $false }
            $printers | Export-Clixml "$workingRoot\Printers.xml"
        } catch {
            $msg = "Failed to capture printers: $_"
            Write-Warning $msg
            Add-Content -Path $ErrorLog -Value $msg
        }
    }

    # Sticky Notes
    if ($IncludeItems -contains "StickyNotes") {
        $stickyPath = "$env:LOCALAPPDATA\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState"
        if (Test-Path $stickyPath) {
            Write-Host "Capturing Sticky Notes..." -ForegroundColor Cyan
            try { Copy-Item $stickyPath (Join-Path $workingRoot "StickyNotes") -Recurse -Force -ErrorAction Stop } catch {
                $msg = "Failed to capture Sticky Notes: $_"
                Write-Warning $msg
                Add-Content -Path $ErrorLog -Value $msg
            }
        }
    }

    # Manifest
    try {
        [PSCustomObject]@{
            User        = $user
            Computer    = $computer
            Timestamp   = (Get-Date).ToString("o")
            Browsers    = if ($IncludeItems -contains "Browsers") { $browserPaths.Keys } else { @() }
            WiFiSSIDs   = $wifiProfiles
        } | ConvertTo-Json | Out-File "$workingRoot\manifest.json"
    } catch {
        $msg = "Failed to create manifest: $_"
        Write-Warning $msg
        Add-Content -Path $ErrorLog -Value $msg
    }

    # Package
    Write-Host "Packaging captured data..." -ForegroundColor Cyan
    try {
        if ($Encrypt) {
            & $SevenZip a -tzip $ZipPath "$workingRoot\*" -p"$Password" -mem=AES256 -y | Out-Null
        } else {
            Compress-Archive -Path "$workingRoot\*" -DestinationPath $ZipPath -Force
        }
        Write-Host "Capture complete -> $ZipPath" -ForegroundColor Green
    } catch {
        $msg = "Failed to create ZIP package: $_"
        Write-Error $msg
        Add-Content -Path $ErrorLog -Value $msg
        throw $msg
    } finally {
        try { Remove-Item $workingRoot -Recurse -Force } catch {}
    }
}

# Restore Function (Robust)
function Restore-UserData {
    param ($ZipPath)

    if (-not (Test-Path $ZipPath)) { throw "File not found: $ZipPath" }

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $restoreRoot = Join-Path $env:TEMP "UserMigrationRestore-$timestamp"
    try { New-Item -ItemType Directory -Path $restoreRoot | Out-Null } catch {}

    Write-Host "Extracting archive..." -ForegroundColor Cyan
    try {
        if ($Encrypt) {
            & $SevenZip x $ZipPath -o"$restoreRoot" -p"$Password" -y | Out-Null
        } else {
            Expand-Archive $ZipPath -DestinationPath $restoreRoot -Force
        }
    } catch {
        $msg = "Failed to extract archive: $_"
        Write-Error $msg
        Add-Content -Path $ErrorLog -Value $msg
        throw $msg
    }

    # Browsers
    $browserRestorePaths = @{
        "Chrome"  = "$env:LOCALAPPDATA\Google\Chrome\User Data"
        "Edge"    = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
        "Firefox" = "$env:APPDATA\Mozilla\Firefox"
        "Opera"   = "$env:APPDATA\Opera Software"
    }

    Write-Host "Closing browsers..." -ForegroundColor Cyan
    try { Get-Process "chrome","msedge","firefox","opera" -ErrorAction SilentlyContinue | Stop-Process -Force } catch {}

    foreach ($browser in $browserRestorePaths.Keys) {
        $src = Join-Path $restoreRoot $browser
        if (Test-Path $src) {
            try {
                Copy-Item $src -Destination $browserRestorePaths[$browser] -Recurse -Force -ErrorAction Stop
                Write-Host "$browser restored successfully." -ForegroundColor Green
            } catch {
                $msg = "Failed to restore ${browser}: $_"
                Write-Warning $msg
                Add-Content -Path $ErrorLog -Value $msg
            }
        }
    }

    # Wi-Fi
    $wifiDir = Join-Path $restoreRoot "WiFi"
    if (Test-Path $wifiDir) {
        Get-ChildItem $wifiDir -Filter "*.xml" | ForEach-Object {
            try {
                $profileName = ($_ | Select-Xml -XPath "//name").Node.InnerText
                $existingProfiles = netsh wlan show profiles | Select-String $profileName
                if (-not $existingProfiles) {
                    Write-Host "Restoring Wi-Fi profile: $profileName" -ForegroundColor Green
                    netsh wlan add profile filename="$($_.FullName)" user=all | Out-Null
                } else {
                    Write-Host "Wi-Fi profile $profileName already exists, skipping." -ForegroundColor Yellow
                }
            } catch {
                $msg = "Failed to restore Wi-Fi profile: $_"
                Write-Warning $msg
                Add-Content -Path $ErrorLog -Value $msg
            }
        }
    }

    # VPN
    $vpnDir = Join-Path $restoreRoot "VPN"
    $winVpn = Join-Path $vpnDir "WindowsVPN.xml"
    if (Test-Path $winVpn) {
        try {
            Import-Clixml $winVpn | ForEach-Object {
                if (-not (Get-VpnConnection -Name $_.Name -ErrorAction SilentlyContinue)) {
                    Write-Host "Restoring VPN: $($_.Name)" -ForegroundColor Green
                    Add-VpnConnection @$_ -Force -AllUserConnection
                } else {
                    Write-Host "VPN connection $($_.Name) already exists, skipping." -ForegroundColor Yellow
                }
            }
        } catch {
            $msg = "Failed to restore Windows VPN connections: $_"
            Write-Warning $msg
            Add-Content -Path $ErrorLog -Value $msg
        }
    }

    # OpenVPN
    $openVpnSrc = Join-Path $vpnDir "OpenVPN"
    if (Test-Path $openVpnSrc) {
        $destPaths = @("$env:USERPROFILE\OpenVPN\config","C:\Program Files\OpenVPN\config")
        foreach ($dst in $destPaths) {
            try {
                Write-Host "Restoring OpenVPN configs to $dst" -ForegroundColor Green
                New-Item -ItemType Directory -Path $dst -Force | Out-Null
                Copy-Item "$openVpnSrc\*" $dst -Recurse -Force
            } catch {
                $msg = "Failed to restore OpenVPN configs to ${dst}: $_"
                Write-Warning $msg
                Add-Content -Path $ErrorLog -Value $msg
            }
        }
    }

    # Outlook Signatures
    $sigSrc = Join-Path $restoreRoot "OutlookSignatures"
    if (Test-Path $sigSrc) {
        try { Copy-Item $sigSrc "$env:APPDATA\Microsoft\Signatures" -Recurse -Force } catch {
            $msg = "Failed to restore Outlook signatures: $_"
            Write-Warning $msg
            Add-Content -Path $ErrorLog -Value $msg
        }
    }

    # Mapped Drives
    $mappedDrivesFile = Join-Path $restoreRoot "MappedDrives.xml"
    if (Test-Path $mappedDrivesFile) {
        try {
            Import-Clixml $mappedDrivesFile | ForEach-Object {
                if (-not (Get-PSDrive $_.Name -ErrorAction SilentlyContinue)) {
                    New-PSDrive -Name $_.Name -PSProvider FileSystem -Root $_.Root -Persist
                    Write-Host "Mapped drive $_.Name restored." -ForegroundColor Green
                }
            }
        } catch {
            $msg = "Failed to restore mapped drives: $_"
            Write-Warning $msg
            Add-Content -Path $ErrorLog -Value $msg
        }
    }

    # Printers
    $printersFile = Join-Path $restoreRoot "Printers.xml"
    if (Test-Path $printersFile) {
        try {
            Import-Clixml $printersFile | ForEach-Object {
                try { Add-Printer -ConnectionName $_.Name } catch {}
            }
        } catch {
            $msg = "Failed to restore printers: $_"
            Write-Warning $msg
            Add-Content -Path $ErrorLog -Value $msg
        }
    }

    # Sticky Notes
    $stickySrc = Join-Path $restoreRoot "StickyNotes"
    $stickyDest = "$env:LOCALAPPDATA\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState"
    if (Test-Path $stickySrc) {
        try {
            Get-Process "StickyNotes" -ErrorAction SilentlyContinue | Stop-Process -Force
        } catch {}
        try { Copy-Item "$stickySrc\*" $stickyDest -Recurse -Force } catch {
            $msg = "Failed to restore Sticky Notes: $_"
            Write-Warning $msg
            Add-Content -Path $ErrorLog -Value $msg
        }
    }

    Write-Host "Restore complete. Reboot recommended." -ForegroundColor Green
}

# Execute
switch ($Mode) {
    "Capture" { Backup-UserData -ZipPath $Path -IncludeItems $Include }
    "Restore" { Restore-UserData -ZipPath $Path }
}
