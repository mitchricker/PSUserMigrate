# Resolve module path dynamically
$ModuleRoot = Resolve-Path "$PSScriptRoot\.."
$ModulePath = Join-Path $ModuleRoot "PSUserMigrate.psm1"

function Import-TestModule {
    <#
    .SYNOPSIS
        Imports the PSUserMigrate module for testing, removing any existing version first.
    #>
    if (Get-Module PSUserMigrate) {
        Remove-Module PSUserMigrate -ErrorAction SilentlyContinue
    }
    Import-Module $ModulePath -Force
}

function New-TestZipPath {
    <#
    .SYNOPSIS
        Returns a unique temporary zip path for tests.
    #>
    Join-Path $env:TEMP ("test-" + [guid]::NewGuid() + ".zip")
}