. "$PSScriptRoot\TestHelpers.ps1"

Describe "Backup-UserData" {

    BeforeAll {
        . "$PSScriptRoot\TestHelpers.ps1"
        Import-TestModule
    }

    Context "Parameter Validation" {

        It "Throws when encryption is requested without password" {
            { Backup-UserData -Path "x.zip" -Encrypt } | Should -Throw
        }

        It "Accepts SecureString password" {
            $pw = ConvertTo-SecureString "test" -AsPlainText -Force
            Mock Compress-Archive {}

            { Backup-UserData -Path "x.zip" -Encrypt:$false -Password $pw } | Should -Not -Throw
        }
    }

    Context "Core Behavior (Mocked)" {

        BeforeEach {
            Mock Compress-Archive {}
            Mock Test-7Zip { "C:\Program Files\7-Zip\7z.exe" }
            Mock ConvertTo-PlainText { "plaintext" }
            Mock netsh {}
            Mock Get-VpnConnection { @() }
            Mock Get-Printer { @() }
        }

        It "Calls Compress-Archive when not encrypted" {
            Backup-UserData -Path "test.zip"

            Assert-MockCalled Compress-Archive -Times 1
        }

        It "Calls 7zip when encryption enabled" {
            $pw = ConvertTo-SecureString "test" -AsPlainText -Force

            Backup-UserData -Path "test.zip" -Encrypt -Password $pw

            Assert-MockCalled Test-7Zip -Times 1
            Assert-MockCalled ConvertTo-PlainText -Times 1
        }

        It "Creates working directory" {
            Mock New-Item { return @{ FullName = "C:\temp\test" } }

            Backup-UserData -Path "test.zip"

            Assert-MockCalled New-Item -Times 1
        }
    }

    Context "Filesystem Integration" {

        It "Creates a zip file" {
            $path = New-TestZipPath

            Backup-UserData -Path $path

            Test-Path $path | Should -BeTrue

            Remove-Item $path -Force
        }

        It "Creates non-empty archive" {
            $path = New-TestZipPath

            Backup-UserData -Path $path

            (Get-Item $path).Length | Should -BeGreaterThan 0

            Remove-Item $path -Force
        }
    }

    Context "Component Selection" {

        BeforeEach {
            Mock Compress-Archive {}
            Mock netsh {}
        }

        It "Only processes selected components" {
            Backup-UserData -Path "test.zip" -Include @("WiFi")

            Assert-MockCalled netsh -TimesGreaterThan 0
        }
    }
}