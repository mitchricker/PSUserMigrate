# Load private functions first
Get-ChildItem "$PSScriptRoot\Private\*.ps1" | ForEach-Object { . $_ }

# Load public functions
Get-ChildItem "$PSScriptRoot\Public\*.ps1" | ForEach-Object { . $_ }

Export-ModuleMember -Function Backup-UserData, Restore-UserData
