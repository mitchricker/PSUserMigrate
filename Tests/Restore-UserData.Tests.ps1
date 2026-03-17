. "$PSScriptRoot\TestHelpers.ps1"

Describe "Restore-UserData" {

    BeforeAll {
        . "$PSScriptRoot\TestHelpers.ps1"
        Import-TestModule
    }

    Context "Validation" {

        It "Throws if archive does not exist" {
            { Restore-UserData -Path "C:\doesnotexist.zip" } | Should -Throw
        }
    }

    Context "Mocked Behavior" {

        BeforeEach {
            Mock Expand-Archive {}
            Mock Test-7Zip { "C:\Program Files\7-Zip\7z.exe" }
            Mock ConvertTo-PlainText { "plaintext" }
            Mock Get-Process { @() }
            Mock Stop-Process {}
            Mock netsh {}
            Mock Add-VpnConnection {}
            Mock Add-Printer {}
        }

        It "Calls Expand-Archive when not encrypted" {
            Mock Test-Path { $true }

            Restore-UserData -Path "test.zip"

            Assert-MockCalled Expand-Archive -Times 1
        }

        It "Calls 7zip when encrypted" {
            Mock Test-Path { $true }

            $pw = ConvertTo-SecureString "test" -AsPlainText -Force

            Restore-UserData -Path "test.zip" -Encrypt -Password $pw

            Assert-MockCalled Test-7Zip -Times 1
        }

        It "Stops browser processes" {
            Mock Test-Path { $true }

            Restore-UserData -Path "test.zip"

            Assert-MockCalled Stop-Process
        }
    }

    Context "Integration" {

        It "Extracts a real archive" {
            $zip = New-TestZipPath
            $tempDir = Join-Path $env:TEMP ([guid]::NewGuid())

            New-Item $tempDir -ItemType Directory | Out-Null
            "test" | Out-File (Join-Path $tempDir "file.txt")

            Compress-Archive "$tempDir\*" $zip

            Restore-UserData -Path $zip

            Test-Path $zip | Should -BeTrue

            Remove-Item $zip -Force
            Remove-Item $tempDir -Recurse -Force
        }
    }
}