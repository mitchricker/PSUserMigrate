function Write-Log {
    param (
        [string]$Message,
        [ValidateSet("Info","Warn","Error")]
        [string]$Level = "Info"
    )

    $logFile = "$env:TEMP\UserMigration.log"
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $entry = "[$timestamp][$Level] $Message"
    Add-Content -Path $logFile -Value $entry

    switch ($Level) {
        "Info" { Write-Verbose $Message }
        "Warn"  { Write-Warning $Message }
        "Error" { Write-Error $Message }
    }
}
