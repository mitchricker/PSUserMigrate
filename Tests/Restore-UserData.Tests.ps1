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
            # Mocks for all helper and system commands used in Restore-UserData
            Mock Test-Path { $true }
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
            Restore-UserData -Path "test.zip"

            Assert-MockCalled Expand-Archive -Exactly 1
        }

        It "Calls 7zip when encrypted" {
            $pw = ConvertTo-SecureString "test" -AsPlainText -Force

            Restore-UserData -Path "test.zip" -Encrypt -Password $pw

            Assert-MockCalled Test-7Zip -Exactly 1
            Assert-MockCalled ConvertTo-PlainText -AtLeast 1
        }

        It "Stops browser processes" {
            Restore-UserData -Path "test.zip"

            Assert-MockCalled Stop-Process -AtLeast 1
        }
    }

    Context "Integration" {
        It "Extracts a real archive" {
            # Prepare test zip
            $zip = New-TestZipPath
            $tempDir = Join-Path $env:TEMP ([guid]::NewGuid())

            New-Item $tempDir -ItemType Directory | Out-Null
            "test" | Out-File (Join-Path $tempDir "file.txt")

            Compress-Archive "$tempDir\*" $zip

            # Run restore
            Restore-UserData -Path $zip

            # Verify zip still exists
            Test-Path $zip | Should -BeTrue

            # Cleanup
            Remove-Item $zip -Force
            Remove-Item $tempDir -Recurse -Force
        }
    }
}
