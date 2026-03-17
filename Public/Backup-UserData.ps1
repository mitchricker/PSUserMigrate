function Backup-UserData {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Path,

        [ValidateSet("Browsers","WiFi","VPN","Signatures","MappedDrives","Printers","StickyNotes")]
        [string[]]$Include,

        [switch]$Encrypt,

        [SecureString]$Password
    )

    $ErrorActionPreference = "Stop"

    if ($Encrypt -and -not $Password) {
        throw "Encryption requires a password."
    }

    if (-not $Include) {
        $Include = @("Browsers","WiFi","VPN","Signatures","MappedDrives","Printers","StickyNotes")
    }

    if ($Encrypt) {
        $SevenZip = Test-7Zip
        $PlainPassword = ConvertTo-PlainText $Password
    }

    $workingRoot = Join-Path $env:TEMP "UserMigration-$([guid]::NewGuid())"
    New-Item -ItemType Directory -Path $workingRoot | Out-Null

    # --- Browsers ---
    if ($Include -contains "Browsers") {
        Write-Log "Capturing browsers..."

        $paths = @{
            Chrome  = "$env:LOCALAPPDATA\Google\Chrome\User Data"
            Edge    = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
            Firefox = "$env:APPDATA\Mozilla\Firefox"
            Opera   = "$env:APPDATA\Opera Software"
        }

        foreach ($k in $paths.Keys) {
            if (Test-Path $paths[$k]) {
                Copy-Item $paths[$k] "$workingRoot\$k" -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # --- WiFi ---
    if ($Include -contains "WiFi") {
        Write-Log "Capturing WiFi..."

        $wifiDir = Join-Path $workingRoot "WiFi"
        New-Item -ItemType Directory $wifiDir -Force | Out-Null

        netsh wlan show profiles |
            Select-String "All User Profile" |
            ForEach-Object {
                $name = ($_ -split ":")[1].Trim()
                netsh wlan export profile name="$name" key=clear folder="$wifiDir" | Out-Null
            }
    }

    # --- VPN ---
    if ($Include -contains "VPN") {
        Write-Log "Capturing VPN..."

        $vpnDir = Join-Path $workingRoot "VPN"
        New-Item $vpnDir -ItemType Directory -Force | Out-Null

        Get-VpnConnection -AllUserConnection | Export-Clixml "$vpnDir\WindowsVPN.xml" -ErrorAction SilentlyContinue
    }

    # --- Signatures ---
    if ($Include -contains "Signatures") {
        Copy-Item "$env:APPDATA\Microsoft\Signatures" "$workingRoot\Signatures" -Recurse -Force -ErrorAction SilentlyContinue
    }

    # --- Mapped Drives ---
    if ($Include -contains "MappedDrives") {
        Get-PSDrive -PSProvider FileSystem |
            Where-Object { $_.Root -like "\\*" } |
            Export-Clixml "$workingRoot\MappedDrives.xml"
    }

    # --- Printers ---
    if ($Include -contains "Printers") {
        Get-Printer | Export-Clixml "$workingRoot\Printers.xml"
    }

    # --- Sticky Notes ---
    if ($Include -contains "StickyNotes") {
        $sticky = "$env:LOCALAPPDATA\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState"
        if (Test-Path $sticky) {
            Copy-Item $sticky "$workingRoot\StickyNotes" -Recurse -Force
        }
    }

    # --- Package ---
    Write-Log "Packaging archive..."

    if ($Encrypt) {
        & $SevenZip a -tzip $Path "$workingRoot\*" -p"$PlainPassword" -mem=AES256 -y | Out-Null
    } else {
        Compress-Archive "$workingRoot\*" $Path -Force
    }

    Remove-Item $workingRoot -Recurse -Force
    Write-Log "Backup complete: $Path"
}
