# Windows Update Reboot Control

`WindowsUpdateRebootControl.ps1` is a small, reversible PowerShell policy tool
for Windows machines whose update installation and reboot timing must remain
under operator control.

It audits, applies, verifies, and restores documented Windows Update policy
registry values. It does **not** disable Windows services, modify protected
scheduled tasks, restart services, or reboot the machine.

Open PowerShell as Administrator and paste this one-liner:

```powershell
Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/w0ot-net/windows_update_reboot_control/main/WindowsUpdateRebootControl.ps1' -ErrorAction Stop | Invoke-Expression
```

The default action applies the `StrictManual` profile, saves the previous policy
state, and verifies the result. Running it again is supported.

## Important limitation

Windows client editions do not offer a supported universal "never reboot for
updates" switch. Microsoft's `NoAutoRebootWithLoggedOnUsers` policy applies to
scheduled installations and signed-in users; inactive RDP sessions do not count,
and a restart explicitly scheduled by a user overrides it.

For that reason, the default `StrictManual` mode disables automatic update
installation. The operator must check for and install updates during a planned
maintenance window, then reboot deliberately. This controls the path to an
update-required reboot rather than relying on brittle service or task hacks.

## Modes

| Mode | Behavior | Intended use |
| --- | --- | --- |
| `StrictManual` | Disables automatic updates and leaves download, installation, and reboot to the operator. | Unattended lab VMs and research workstations. |
| `ClientNotify` | Windows scans and notifies, but the user initiates download and installation. | Windows 10/11 systems with an active operator. |
| `ServerNotify` | Downloads updates, then notifies before installation and restart (`AUOptions=7`). | Windows Server 2016 or later only. |

All modes also set the logged-on-user restart guard and disable the legacy
scheduled-time auto-restart policy. These are defense-in-depth values, not an
absolute restart interlock.

## Advanced usage

Open an elevated Windows PowerShell or PowerShell 7 session:

```powershell
# Read-only audit
.\WindowsUpdateRebootControl.ps1 -Action Audit -Mode StrictManual |
    ConvertTo-Json -Depth 10

# Apply and independently verify the strict profile (also the default action)
.\WindowsUpdateRebootControl.ps1 -Action Apply -Mode StrictManual

# Restore the state captured before the first mutation
.\WindowsUpdateRebootControl.ps1 -Action Restore
```

Use `-Confirm` when an interactive confirmation is desired and `-WhatIf` to
preview an apply or restore action.

The first mutation stores a machine-bound baseline at:

```text
%ProgramData%\WindowsUpdateRebootControl\baseline.json
```

The baseline is retained after restoration so it can be reviewed and restoration
can be repeated. Use `-BackupPath` to choose another local path.

## Managed devices and deadline policies

The script refuses to apply local settings to a domain-joined or MDM-managed
device unless `-AllowManagedDevice` is supplied. Local deadline/compliance
values also cause a refusal unless their removal is explicitly authorized with
`-ClearConflictingDeadlinePolicies`.

MDM deadline policies are never removed locally. They must be removed at their
management source because Windows can reapply them and they can override local
download, installation, and restart behavior.

## Security responsibility

`StrictManual` trades unattended patching for reboot control. Establish a regular
maintenance window, review pending security updates, install them, and reboot.
Do not use this mode on machines that nobody is responsible for patching.

## Supported systems

- Windows PowerShell 5.1 or PowerShell 7+
- Windows 10 and Windows 11 editions that honor Windows Update administrative
  policy
- Windows Server 2016 or later (`ServerNotify` is server-only)

Run as administrator for `Apply` and `Restore`. `Audit` is read-only.

## Microsoft documentation

- [Configure Automatic Updates](https://learn.microsoft.com/windows-server/administration/windows-server-update-services/deploy/4-configure-group-policy-settings-for-automatic-updates)
- [Manage device restarts after updates](https://learn.microsoft.com/windows/deployment/update/waas-restart)
- [Manage additional Windows Update settings](https://learn.microsoft.com/windows/deployment/update/waas-wu-settings)

## License

[MIT](LICENSE)
