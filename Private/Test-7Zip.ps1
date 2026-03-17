function Test-7Zip {
    param (
        [string]$Path = "C:\Program Files\7-Zip\7z.exe"
    )

    if (Test-Path $Path) { return $Path }

    Write-Log "7-Zip not found. Installing via winget..." "Warn"

    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install --id=7zip.7zip -e --silent | Out-Null

        for ($i = 0; $i -lt 10; $i++) {
            Start-Sleep 5
            if (Test-Path $Path) { return $Path }
        }

        throw "7-Zip install failed."
    }

    throw "winget not available. Install 7-Zip manually."
}