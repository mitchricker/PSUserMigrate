@{
    RootModule        = 'PSUserMigrate.psm1'
    ModuleVersion     = '0.2.3'
    GUID              = '13d898bd-c157-45e0-9af4-f5b28d5f9eff'
    Author            = 'Mitch Ricker'
    CompanyName       = 'Automating.Systems'
    Description       = 'PowerShell module to backup and restore user data with optional encryption.'

    FunctionsToExport = @(
        'Backup-UserData',
        'Restore-UserData'
    )

    PowerShellVersion = '7.0'

    PrivateData       = @{
        PSData = @{
            ProjectUri = 'https://github.com/mitchricker/PSUserMigrate'
            LicenseUri = 'https://opensource.org/licenses/MIT'
        }
    }
}
