# PSUserMigrate

A PowerShell module for capturing and restoring user environment settings during workstation migrations, refreshes, and break/fix scenarios.

This tool helps reduce common post-migration issues (missing browser data, Wi-Fi, VPNs, etc.) that typically result in helpdesk calls.

---

## Overview

PSUserMigrate captures a user’s environment into a ZIP archive and restores it on the same or another machine.

- `Backup-UserData` allows selective inclusion of components
- `Restore-UserData` restores *everything present in the backup*
- Supports optional AES-256 encryption using 7-Zip

> A backup created with `-Encrypt` **must** be restored using the same password.

Rebooting is recommended after restore to ensure all changes are applied.

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
- Selective capture support
- Automatic 7-Zip installation via `winget` (if needed)
- Migration manifest generation (basic audit info)
- Designed for helpdesk and field technician use

---

## Requirements

- Windows 10 / 11
- PowerShell 5.1 or newer
- Administrator privileges required for:
  - VPNs
  - Printers
  - Mapped drives
- `winget` (only required if using encryption and 7-Zip is not installed)

---

## Installation

### From local repository

```powershell
Import-Module .\PSUserMigrate
```
---
## Usage
### Capture all user data
```PowerShell
Backup-UserData -Path .\backup\UserData.zip
```

### Capture selected components

```PowerShell
Backup-UserData `
  -Path .\backup\UserData.zip `
  -Include Browsers,WiFi,StickyNotes
```

### Capture with encryption

```PowerShell
Backup-UserData `
  -Path .\backup\UserData.zip `
  -Encrypt `
  -Password (Read-Host -AsSecureString)
```

### Restore from backup
```PowerShell
Restore-UserData -Path .\backup\UserData.zip
```

### Restore encrypted backup
```PowerShell
Restore-UserData `
  -Path .\backup\UserData.zip `
  -Encrypt `
  -Password (Read-Host -AsSecureString)
```

---

## Notes & Limitations

  - Restore is not selective — all available data in the archive will be applied

  - Browser restoration overwrites existing profiles

  - Wi-Fi profiles are restored only if not already present

  - Some operations may fail without admin privileges

  - Open applications (browsers, Sticky Notes) may interfere with restore

  - Encryption requires 7-Zip (installed automatically if winget is available)

---

## Recommended Workflow

  1. Run capture on the source machine

  2. Transfer the ZIP file to the destination machine

  3. Run restore

  4. Reboot the system

## Troubleshooting

  - Ensure PowerShell is running as Administrator when required

  - Verify the ZIP file path is accessible

  - Confirm password correctness for encrypted archives

  - Check logs in: `$env:TEMP\UserMigration.log`

---

## License

MIT

---
