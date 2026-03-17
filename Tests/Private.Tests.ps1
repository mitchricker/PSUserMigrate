. "$PSScriptRoot\TestHelpers.ps1"

Describe "Private Functions" {

    BeforeAll {
        . "$PSScriptRoot\TestHelpers.ps1"
        Import-TestModule
    }

    Context "ConvertTo-PlainText" {

        It "Converts SecureString to plaintext" {
            $secure = ConvertTo-SecureString "hello" -AsPlainText -Force

            $result = ConvertTo-PlainText $secure

            $result | Should -Be "hello"
        }
    }

    Context "Test-7Zip" {

        BeforeEach {
            # Clear previous mocks to avoid interference
            Remove-Mock -CommandName Test-Path -ErrorAction SilentlyContinue
            Remove-Mock -CommandName Get-Command -ErrorAction SilentlyContinue
        }

        It "Returns path if 7zip exists" {
            Mock Test-Path { $true }

            $result = Test-7Zip

            $result | Should -Match "7z.exe"
        }

        It "Throws if winget not available and 7zip missing" {
            Mock Test-Path { $false }
            Mock Get-Command { $null }

            { Test-7Zip } | Should -Throw
        }
    }

    Context "Write-Log" {

        BeforeEach {
            # Remove any existing log before each test
            $log = "$env:TEMP\UserMigration.log"
            if (Test-Path $log) { Remove-Item $log -Force }
        }

        It "Writes log file" {
            $log = "$env:TEMP\UserMigration.log"

            Write-Log "Test message"

            Test-Path $log | Should -BeTrue
        }
    }
}