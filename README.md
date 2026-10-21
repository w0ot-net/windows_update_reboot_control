# Windows Update Reboot Control

A single, reversible PowerShell script for keeping Windows Update installation
and reboot timing under operator control.

Console output is concise and colorized by default. JSON and PowerShell objects
are available explicitly for automation.

Open PowerShell as Administrator and paste one of the commands below.

## Apply the recommended policy

`StrictManual` disables automatic update installation. You decide when to check,
install, and reboot.

```powershell
Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/w0ot-net/windows_update_reboot_control/main/WindowsUpdateRebootControl.ps1' -ErrorAction Stop | Invoke-Expression
```

## Other copy/paste commands

Audit without changing anything:

```powershell
& ([scriptblock]::Create((Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/w0ot-net/windows_update_reboot_control/main/WindowsUpdateRebootControl.ps1' -ErrorAction Stop))) -Action Audit -Mode StrictManual
```

Apply `ClientNotify` on Windows 10 or 11:

```powershell
& ([scriptblock]::Create((Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/w0ot-net/windows_update_reboot_control/main/WindowsUpdateRebootControl.ps1' -ErrorAction Stop))) -Action Apply -Mode ClientNotify
```

Apply `ServerNotify` on Windows Server 2016 or later:

```powershell
& ([scriptblock]::Create((Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/w0ot-net/windows_update_reboot_control/main/WindowsUpdateRebootControl.ps1' -ErrorAction Stop))) -Action Apply -Mode ServerNotify
```

Preview the recommended policy without changing anything:

```powershell
& ([scriptblock]::Create((Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/w0ot-net/windows_update_reboot_control/main/WindowsUpdateRebootControl.ps1' -ErrorAction Stop))) -Action Apply -Mode StrictManual -WhatIf
```

Restore the policy state saved before the first apply:

```powershell
& ([scriptblock]::Create((Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/w0ot-net/windows_update_reboot_control/main/WindowsUpdateRebootControl.ps1' -ErrorAction Stop))) -Action Restore
```

## Arguments

| Argument | Values or behavior |
| --- | --- |
| `-Action` | `Audit`, `Apply`, or `Restore` |
| `-Mode` | `StrictManual`, `ClientNotify`, or `ServerNotify` |
| `-BackupPath` | Use a backup path other than `%ProgramData%\WindowsUpdateRebootControl\baseline.json` |
| `-OutputFormat` | `Human` (default), `Json`, or `Object` |
| `-WhatIf` | Preview `Apply` or `Restore` |
| `-Confirm` | Ask for confirmation before changing policy |
| `-AllowManagedDevice` | Permit local changes on a domain-joined or MDM-managed device |
| `-ClearConflictingDeadlinePolicies` | Remove conflicting local deadline policies after they have been reviewed |

Arguments can be appended to any applicable download command. For example:

```powershell
& ([scriptblock]::Create((Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/w0ot-net/windows_update_reboot_control/main/WindowsUpdateRebootControl.ps1' -ErrorAction Stop))) -Action Apply -Mode StrictManual -BackupPath 'C:\WindowsUpdateRebootControl\baseline.json' -AllowManagedDevice
```

## Notes

- `StrictManual` is recommended for unattended VMs. It requires you to apply
  security updates manually.
- `ClientNotify` scans and notifies, but the operator starts download and
  installation.
- `ServerNotify` downloads updates and then notifies before installation and
  restart. It is server-only.
- Windows client editions have no supported universal "never reboot" switch.
  The strict mode prevents automatic update installation so Windows Update
  cannot autonomously reach a restart-required state.
- The script verifies its changes, saves a machine-bound baseline, and never
  restarts Windows or services.
- MDM deadline policies must be removed at their management source.

Microsoft references: [automatic update policy](https://learn.microsoft.com/windows-server/administration/windows-server-update-services/deploy/4-configure-group-policy-settings-for-automatic-updates),
[restart policy](https://learn.microsoft.com/windows/deployment/update/waas-restart),
and [additional settings](https://learn.microsoft.com/windows/deployment/update/waas-wu-settings).

[MIT licensed](LICENSE).
