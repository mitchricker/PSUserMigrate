# Resolve module path dynamically
$ModuleRoot = Resolve-Path "$PSScriptRoot\.."
$ModulePath = Join-Path $ModuleRoot "PSUserMigrate.psm1"

function Import-TestModule {
    Remove-Module PSUserMigrate -ErrorAction SilentlyContinue
    Import-Module $ModulePath -Force
}

function New-TestZipPath {
    return Join-Path $env:TEMP ("test-" + [guid]::NewGuid() + ".zip")
}