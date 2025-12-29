# PSUserMigrate

A simple PowerShell script to automate migrating user settings that commonly result in helpdesk calls if forgotten.

This script captures a user’s environment into a ZIP file and restores it on the same or another machine. It’s designed for workstation refreshes, break/fix scenarios, and user migrations.

When using `-Mode Capture`, you may specifically target what should be captured in the backup via `-Include`.  
`-Mode Restore` will attempt to restore **everything present in the backup** (restore is not selective).

A capture that uses `-Encrypt -Password (Read-Host -AsSecureString)` **must** also be restored using the same parameters.

It is advised to reboot after completing a restore to ensure all changes are applied correctly.

---

## Features

- Capture and restore:
  - Browsers (Chrome, Edge, Firefox, Opera)
  - Wi-Fi profiles (exported as XML)
  - VPN connections (Windows VPN + OpenVPN configs)
  - Outlook signatures
  - Mapped network drives
  - Printers
  - Sticky Notes
- Optional AES-256 ZIP encryption (via 7-Zip)
- Selective capture of components
- Automatic 7-Zip installation via `winget` (if required)
- Creates a migration manifest for auditing
- Designed to be safe for helpdesk and field use

---

## Requirements

- Windows 10 / 11
- PowerShell 5.1 or newer
- Administrator privileges for:
  - VPNs
  - Printers
  - Mapped drives
- `winget` (only required if using encryption and 7-Zip is not already installed)

---

## Usage

### Capture all user data

```powershell
powershell -ExecutionPolicy Bypass -File .\PSUserMigrate.ps1 `
  -Mode Capture `
  -Path .\backup\UserData.zip
```
### Capture only selected components (selective migration)
```powershell
powershell -ExecutionPolicy Bypass -File .\PSUserMigrate.ps1 `
  -Mode Capture `
  -Path .\backup\UserData.zip `
  -Include Browsers,WiFi,StickyNotes
```
### Capture with encryption
```powershell
powershell -ExecutionPolicy Bypass -File .\PSUserMigrate.ps1 `
  -Mode Capture `
  -Path .\backup\UserData.zip `
  -Encrypt `
  -Password (Read-Host -AsSecureString)
```
### Restore from an encrypted backup
```powershell
powershell -ExecutionPolicy Bypass -File .\PSUserMigrate.ps1 `
  -Mode Restore `
  -Path .\backup\UserData.zip `
  -Encrypt `
  -Password (Read-Host -AsSecureString)
```
