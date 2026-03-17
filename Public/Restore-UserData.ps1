function Restore-UserData {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Path,

        [switch]$Encrypt,

        [SecureString]$Password
    )

    if (-not (Test-Path $Path)) {
        throw "Archive not found."
    }

    if ($Encrypt) {
        $SevenZip = Test-7Zip
        $PlainPassword = ConvertTo-PlainText $Password
    }

    $restoreRoot = Join-Path $env:TEMP "UserRestore-$([guid]::NewGuid())"
    New-Item $restoreRoot -ItemType Directory | Out-Null

    Write-Log "Extracting archive..."

    if ($Encrypt) {
        & $SevenZip x $Path -o"$restoreRoot" -p"$PlainPassword" -y | Out-Null
    } else {
        Expand-Archive $Path $restoreRoot -Force
    }

    # --- Browsers ---
    Get-Process chrome,msedge,firefox,opera -ErrorAction SilentlyContinue | Stop-Process -Force

    $paths = @{
        Chrome  = "$env:LOCALAPPDATA\Google\Chrome\User Data"
        Edge    = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
        Firefox = "$env:APPDATA\Mozilla\Firefox"
        Opera   = "$env:APPDATA\Opera Software"
    }

    foreach ($k in $paths.Keys) {
        $src = Join-Path $restoreRoot $k
        if (Test-Path $src) {
            Copy-Item $src $paths[$k] -Recurse -Force
        }
    }

    # --- WiFi ---
    Get-ChildItem "$restoreRoot\WiFi" -Filter *.xml -ErrorAction SilentlyContinue |
        ForEach-Object {
            netsh wlan add profile filename="$($_.FullName)" user=all | Out-Null
        }

    # --- VPN ---
    $vpn = "$restoreRoot\VPN\WindowsVPN.xml"
    if (Test-Path $vpn) {
        Import-Clixml $vpn | ForEach-Object {
            Add-VpnConnection @$_ -Force -AllUserConnection -ErrorAction SilentlyContinue
        }
    }

    # --- Signatures ---
    Copy-Item "$restoreRoot\Signatures" "$env:APPDATA\Microsoft\Signatures" -Recurse -Force -ErrorAction SilentlyContinue

    # --- Drives ---
    if (Test-Path "$restoreRoot\MappedDrives.xml") {
        Import-Clixml "$restoreRoot\MappedDrives.xml" |
            ForEach-Object {
                New-PSDrive -Name $_.Name -PSProvider FileSystem -Root $_.Root -Persist -ErrorAction SilentlyContinue
            }
    }

    # --- Printers ---
    if (Test-Path "$restoreRoot\Printers.xml") {
        Import-Clixml "$restoreRoot\Printers.xml" |
            ForEach-Object {
                Add-Printer -ConnectionName $_.Name -ErrorAction SilentlyContinue
            }
    }

    # --- Sticky Notes ---
    Copy-Item "$restoreRoot\StickyNotes\*" `
        "$env:LOCALAPPDATA\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState" `
        -Recurse -Force -ErrorAction SilentlyContinue

    Write-Log "Restore complete. Reboot recommended."
}