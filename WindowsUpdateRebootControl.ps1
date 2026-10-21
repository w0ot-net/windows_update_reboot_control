#Requires -Version 5.1

<#
.SYNOPSIS
Audits, applies, or restores Windows Update policies for operator-controlled restarts.

.DESCRIPTION
Windows client editions do not provide a supported universal "never reboot" switch.
The StrictManual mode prevents automatic update installation so an update cannot
autonomously reach a restart-required state. Operators remain responsible for
checking, installing, and rebooting during a maintenance window.

The script writes only documented Windows Update policy registry values. It does
not disable services, alter protected scheduled tasks, restart services, or reboot.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [ValidateSet('Audit', 'Apply', 'Restore')]
    [string]$Action = 'Apply',

    [ValidateSet('StrictManual', 'ClientNotify', 'ServerNotify')]
    [string]$Mode = 'StrictManual',

    [string]$BackupPath,

    [ValidateSet('Human', 'Json', 'Object')]
    [string]$OutputFormat = 'Human',

    [switch]$AllowManagedDevice,

    [switch]$ClearConflictingDeadlinePolicies
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:WindowsUpdatePath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$script:AutomaticUpdatesPath = "$script:WindowsUpdatePath\AU"
$script:MdmUpdatePath = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'

function Assert-Windows {
    if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) {
        throw 'WindowsUpdateRebootControl must run on Windows.'
    }
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $role = [Security.Principal.WindowsBuiltInRole]::Administrator
    if (-not $principal.IsInRole($role)) {
        throw 'Apply and Restore require an elevated PowerShell session.'
    }
}

function Get-DefaultBackupPath {
    $programData = [Environment]::GetFolderPath('CommonApplicationData')
    if ([string]::IsNullOrWhiteSpace($programData)) {
        throw 'Cannot resolve the Windows ProgramData directory.'
    }
    return Join-Path $programData 'WindowsUpdateRebootControl\baseline.json'
}

function Get-MachineContext {
    $os = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem
    $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
    $machineGuid = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid

    [pscustomobject][ordered]@{
        Hostname = [Environment]::MachineName
        MachineGuid = [string]$machineGuid
        ProductName = [string]$operatingSystem.Caption
        DisplayVersion = [string]$os.DisplayVersion
        CurrentBuild = [string]$os.CurrentBuild
        UBR = [int]$os.UBR
        ProductType = [int]$operatingSystem.ProductType
        DomainJoined = [bool]$computer.PartOfDomain
        Domain = [string]$computer.Domain
    }
}

function Get-DesiredValues {
    param([Parameter(Mandatory = $true)][string]$SelectedMode)

    $noAutoUpdate = if ($SelectedMode -eq 'StrictManual') { 1 } else { 0 }
    $auOptions = if ($SelectedMode -eq 'ServerNotify') { 7 } else { 2 }

    @(
        [pscustomobject]@{ Path = $script:AutomaticUpdatesPath; Name = 'NoAutoUpdate'; Value = $noAutoUpdate },
        [pscustomobject]@{ Path = $script:AutomaticUpdatesPath; Name = 'AUOptions'; Value = $auOptions },
        [pscustomobject]@{ Path = $script:AutomaticUpdatesPath; Name = 'NoAutoRebootWithLoggedOnUsers'; Value = 1 },
        [pscustomobject]@{ Path = $script:AutomaticUpdatesPath; Name = 'AlwaysAutoRebootAtScheduledTime'; Value = 0 }
    )
}

function Get-RegistryValueSnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject][ordered]@{
            Path = $Path
            Name = $Name
            Exists = $false
            Kind = $null
            Value = $null
        }
    }

    $key = Get-Item -LiteralPath $Path
    $exists = $key.GetValueNames() -contains $Name
    [pscustomobject][ordered]@{
        Path = $Path
        Name = $Name
        Exists = $exists
        Kind = if ($exists) { [string]$key.GetValueKind($Name) } else { $null }
        Value = if ($exists) { $key.GetValue($Name, $null, 'DoNotExpandEnvironmentNames') } else { $null }
    }
}

function Get-KeySnapshot {
    param([Parameter(Mandatory = $true)][string]$Path)

    [pscustomobject][ordered]@{
        Path = $Path
        Existed = Test-Path -LiteralPath $Path
    }
}

function Get-DeadlineValues {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Source
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return @()
    }

    $key = Get-Item -LiteralPath $Path
    @($key.GetValueNames() | Where-Object { $_ -match '(?i)(deadline|compliance)' } | ForEach-Object {
        [pscustomobject][ordered]@{
            Source = $Source
            Path = $Path
            Name = [string]$_
            Kind = [string]$key.GetValueKind($_)
            Value = $key.GetValue($_, $null, 'DoNotExpandEnvironmentNames')
        }
    })
}

function Get-ManagementState {
    param([Parameter(Mandatory = $true)]$Context)

    $mdmPresent = $false
    if (Test-Path -LiteralPath $script:MdmUpdatePath) {
        $mdmKey = Get-Item -LiteralPath $script:MdmUpdatePath
        $mdmPresent = ($mdmKey.ValueCount -gt 0 -or $mdmKey.SubKeyCount -gt 0)
    }

    $localDeadlines = @(Get-DeadlineValues -Path $script:WindowsUpdatePath -Source 'LocalPolicy')
    $mdmDeadlines = @(Get-DeadlineValues -Path $script:MdmUpdatePath -Source 'PolicyManager')

    [pscustomobject][ordered]@{
        DomainJoined = [bool]$Context.DomainJoined
        Domain = [string]$Context.Domain
        MdmUpdatePolicyPresent = $mdmPresent
        LocalDeadlinePolicies = $localDeadlines
        MdmDeadlinePolicies = $mdmDeadlines
    }
}

function Get-PendingRestartState {
    $rename = $null
    $sessionManager = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    if (Test-Path -LiteralPath $sessionManager) {
        $renameProperty = Get-ItemProperty -LiteralPath $sessionManager -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
        if ($null -ne $renameProperty) {
            $rename = $renameProperty.PendingFileRenameOperations
        }
    }

    [pscustomobject][ordered]@{
        ComponentServicing = Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        WindowsUpdate = Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        PendingFileRename = $null -ne $rename
    }
}

function Get-AuditResult {
    param(
        [Parameter(Mandatory = $true)][string]$SelectedMode,
        [Parameter(Mandatory = $true)][string]$ResultAction,
        [string]$ResultBackupPath,
        [bool]$BackupCreated = $false,
        [bool]$BackupUpdated = $false
    )

    $context = Get-MachineContext
    $management = Get-ManagementState -Context $context
    $desired = @(Get-DesiredValues -SelectedMode $SelectedMode)
    $observed = @()
    $drift = @()

    foreach ($entry in $desired) {
        $snapshot = Get-RegistryValueSnapshot -Path $entry.Path -Name $entry.Name
        $matches = $snapshot.Exists -and $snapshot.Kind -eq 'DWord' -and [int]$snapshot.Value -eq [int]$entry.Value
        $observed += [pscustomobject][ordered]@{
            Path = $entry.Path
            Name = $entry.Name
            ExpectedKind = 'DWord'
            ExpectedValue = [int]$entry.Value
            Exists = [bool]$snapshot.Exists
            ActualKind = $snapshot.Kind
            ActualValue = $snapshot.Value
            Matches = $matches
        }
        if (-not $matches) {
            $drift += $entry.Name
        }
    }

    $supported = -not ($SelectedMode -eq 'ServerNotify' -and $context.ProductType -eq 1)
    $deadlineCount = @($management.LocalDeadlinePolicies).Count + @($management.MdmDeadlinePolicies).Count
    $pending = Get-PendingRestartState
    $warnings = @()
    if ($SelectedMode -eq 'StrictManual') {
        $warnings += 'StrictManual requires you to check for updates, install them, and reboot during a planned maintenance window.'
    } else {
        $warnings += 'This mode reduces automatic restart risk but is not a universal reboot interlock.'
    }
    if ($context.DomainJoined -or $management.MdmUpdatePolicyPresent) {
        $warnings += 'Domain or MDM policy can overwrite local policy values.'
    }
    if ($deadlineCount -gt 0) {
        $warnings += 'Deadline or compliance policy may override update installation or restart behavior.'
    }
    if ($pending.ComponentServicing -or $pending.WindowsUpdate -or $pending.PendingFileRename) {
        $warnings += 'The machine already has at least one pending-restart indicator.'
    }

    [pscustomobject][ordered]@{
        SchemaVersion = 1
        ObservedAtUtc = [DateTime]::UtcNow.ToString('o')
        Action = $ResultAction
        Mode = $SelectedMode
        Supported = $supported
        Compliant = ($supported -and $drift.Count -eq 0 -and $deadlineCount -eq 0)
        Host = [pscustomobject][ordered]@{
            Hostname = $context.Hostname
            ProductName = $context.ProductName
            DisplayVersion = $context.DisplayVersion
            Build = "$($context.CurrentBuild).$($context.UBR)"
            ProductType = $context.ProductType
        }
        Management = $management
        PendingRestart = $pending
        PolicyValues = $observed
        Drift = $drift
        Warnings = $warnings
        BackupPath = $ResultBackupPath
        BackupCreated = $BackupCreated
        BackupUpdated = $BackupUpdated
    }
}

function Get-PolicyDisplayValue {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        $Value,
        [bool]$Exists = $true
    )

    if (-not $Exists) {
        return 'not set'
    }

    switch ($Name) {
        'NoAutoUpdate' {
            if ([int]$Value -eq 1) { return 'disabled' }
            if ([int]$Value -eq 0) { return 'enabled' }
        }
        'AUOptions' {
            switch ([int]$Value) {
                2 { return 'notify before download and installation (2)' }
                3 { return 'download automatically; notify before installation (3)' }
                4 { return 'download and install on a schedule (4)' }
                5 { return 'local administrator chooses (5)' }
                7 { return 'server: notify before installation and restart (7)' }
            }
        }
        'NoAutoRebootWithLoggedOnUsers' {
            if ([int]$Value -eq 1) { return 'enabled' }
            if ([int]$Value -eq 0) { return 'disabled' }
        }
        'AlwaysAutoRebootAtScheduledTime' {
            if ([int]$Value -eq 1) { return 'enabled' }
            if ([int]$Value -eq 0) { return 'disabled' }
        }
    }
    return [string]$Value
}

function Get-PolicyDisplayName {
    param([Parameter(Mandatory = $true)][string]$Name)

    switch ($Name) {
        'NoAutoUpdate' { return 'Automatic update installation' }
        'AUOptions' { return 'Update mode' }
        'NoAutoRebootWithLoggedOnUsers' { return 'Logged-on user restart guard' }
        'AlwaysAutoRebootAtScheduledTime' { return 'Scheduled-time auto-restart' }
        default { return $Name }
    }
}

function Write-HumanAuditResult {
    param([Parameter(Mandatory = $true)]$Result)

    Write-Host ''
    Write-Host 'Windows Update Reboot Control' -ForegroundColor Cyan
    Write-Host '-----------------------------' -ForegroundColor DarkCyan
    Write-Host ('Host:   {0} ({1}, build {2})' -f $Result.Host.Hostname, $Result.Host.ProductName, $Result.Host.Build)
    Write-Host ('Action: {0}' -f $Result.Action)
    Write-Host ('Mode:   {0}' -f $Result.Mode)

    if (-not $Result.Supported) {
        Write-Host 'Status: UNSUPPORTED ON THIS WINDOWS EDITION' -ForegroundColor Red
    } elseif ($Result.Compliant) {
        if ($Result.Action -eq 'Applied') {
            Write-Host 'Status: APPLIED AND VERIFIED' -ForegroundColor Green
        } else {
            Write-Host 'Status: POLICY MATCHES' -ForegroundColor Green
        }
    } elseif ($Result.Action -eq 'ApplyWhatIf') {
        Write-Host 'Status: PREVIEW ONLY - NO CHANGES MADE' -ForegroundColor Yellow
    } else {
        Write-Host 'Status: CHANGES NEEDED' -ForegroundColor Yellow
    }

    Write-Host ''
    Write-Host 'Policy' -ForegroundColor Cyan
    foreach ($entry in $Result.PolicyValues) {
        $displayName = Get-PolicyDisplayName -Name $entry.Name
        $expected = Get-PolicyDisplayValue -Name $entry.Name -Value $entry.ExpectedValue
        $actual = Get-PolicyDisplayValue -Name $entry.Name -Value $entry.ActualValue -Exists $entry.Exists
        if ($entry.Matches) {
            Write-Host '  [OK] ' -ForegroundColor Green -NoNewline
            Write-Host ("{0}: {1}" -f $displayName, $actual)
        } else {
            Write-Host '  [CHANGE] ' -ForegroundColor Yellow -NoNewline
            Write-Host ("{0}: expected {1}; found {2}" -f $displayName, $expected, $actual)
        }
    }

    Write-Host ''
    Write-Host 'Checks' -ForegroundColor Cyan
    $managed = $Result.Management.DomainJoined -or $Result.Management.MdmUpdatePolicyPresent
    if ($managed) {
        Write-Host '  [WARN] ' -ForegroundColor Yellow -NoNewline
        Write-Host 'Domain or MDM management detected.'
    } else {
        Write-Host '  [OK] ' -ForegroundColor Green -NoNewline
        Write-Host 'No domain or MDM update management detected.'
    }

    $deadlineCount = @($Result.Management.LocalDeadlinePolicies).Count + @($Result.Management.MdmDeadlinePolicies).Count
    if ($deadlineCount -gt 0) {
        Write-Host '  [WARN] ' -ForegroundColor Yellow -NoNewline
        Write-Host ("{0} conflicting deadline/compliance policy value(s) detected." -f $deadlineCount)
    } else {
        Write-Host '  [OK] ' -ForegroundColor Green -NoNewline
        Write-Host 'No conflicting deadline policies detected.'
    }

    $pendingNames = @()
    if ($Result.PendingRestart.ComponentServicing) { $pendingNames += 'component servicing' }
    if ($Result.PendingRestart.WindowsUpdate) { $pendingNames += 'Windows Update' }
    if ($Result.PendingRestart.PendingFileRename) { $pendingNames += 'pending file rename' }
    if ($pendingNames.Count -gt 0) {
        Write-Host '  [WARN] ' -ForegroundColor Yellow -NoNewline
        Write-Host ("Pending restart detected: {0}." -f ($pendingNames -join ', '))
    } else {
        Write-Host '  [OK] ' -ForegroundColor Green -NoNewline
        Write-Host 'No pending restart detected.'
    }

    if ($Result.BackupCreated) {
        Write-Host '  [OK] ' -ForegroundColor Green -NoNewline
        Write-Host ("Baseline backup created: {0}" -f $Result.BackupPath)
    } elseif ($Result.BackupUpdated) {
        Write-Host '  [OK] ' -ForegroundColor Green -NoNewline
        Write-Host ("Baseline backup updated: {0}" -f $Result.BackupPath)
    } elseif (-not [string]::IsNullOrWhiteSpace([string]$Result.BackupPath)) {
        Write-Host ("  Backup: {0}" -f $Result.BackupPath) -ForegroundColor DarkGray
    }

    if (@($Result.Warnings).Count -gt 0) {
        Write-Host ''
        Write-Host 'Notes' -ForegroundColor Cyan
        foreach ($warning in $Result.Warnings) {
            Write-Host ("  - {0}" -f $warning) -ForegroundColor DarkYellow
        }
    }
    Write-Host ''
}

function Write-HumanRestoreResult {
    param([Parameter(Mandatory = $true)]$Result)

    Write-Host ''
    Write-Host 'Windows Update Reboot Control' -ForegroundColor Cyan
    Write-Host '-----------------------------' -ForegroundColor DarkCyan
    Write-Host ("Host:   {0}" -f $Result.Hostname)
    Write-Host ("Action: {0}" -f $Result.Action)
    if ($Result.Action -eq 'RestoreWhatIf') {
        Write-Host 'Status: PREVIEW ONLY - NO CHANGES MADE' -ForegroundColor Yellow
    } else {
        Write-Host 'Status: ORIGINAL POLICY RESTORED AND VERIFIED' -ForegroundColor Green
        Write-Host 'Reboot: Not performed' -ForegroundColor Green
    }
    Write-Host ("Backup: {0}" -f $Result.BackupPath) -ForegroundColor DarkGray
    Write-Host ''
}

function Write-Result {
    param(
        [Parameter(Mandatory = $true)]$Result,
        [Parameter(Mandatory = $true)][string]$Format
    )

    switch ($Format) {
        'Json' {
            Write-Output ($Result | ConvertTo-Json -Depth 10)
        }
        'Object' {
            Write-Output $Result
        }
        'Human' {
            if ($Result.Action -like 'Restore*') {
                Write-HumanRestoreResult -Result $Result
            } else {
                Write-HumanAuditResult -Result $Result
            }
        }
    }
}

function Write-JsonAtomically {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    $directory = [IO.Path]::GetDirectoryName($fullPath)
    if (-not (Test-Path -LiteralPath $directory)) {
        $null = New-Item -ItemType Directory -Path $directory -Force
    }

    $temporaryPath = "$fullPath.$PID.tmp"
    $json = $Value | ConvertTo-Json -Depth 10
    [IO.File]::WriteAllText($temporaryPath, $json, (New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $temporaryPath -Destination $fullPath -Force
}

function Ensure-BaselineBackup {
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][array]$ValueSnapshots,
        [Parameter(Mandatory = $true)][array]$KeySnapshots,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$SelectedMode
    )

    $created = $false
    $updated = $false
    if (Test-Path -LiteralPath $Path) {
        $backup = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
        if ([int]$backup.SchemaVersion -ne 1) {
            throw "Unsupported backup schema in $Path"
        }
        if ([string]$backup.MachineGuid -ne [string]$Context.MachineGuid) {
            throw "Backup $Path belongs to a different Windows installation."
        }
    } else {
        $backup = [pscustomobject][ordered]@{
            SchemaVersion = 1
            CreatedAtUtc = [DateTime]::UtcNow.ToString('o')
            UpdatedAtUtc = [DateTime]::UtcNow.ToString('o')
            Hostname = $Context.Hostname
            MachineGuid = $Context.MachineGuid
            InitialMode = $SelectedMode
            Values = @()
            Keys = @()
        }
        $created = $true
    }

    $existingValues = @{}
    foreach ($entry in @($backup.Values)) {
        $existingValues["$($entry.Path)`n$($entry.Name)"] = $true
    }
    foreach ($entry in $ValueSnapshots) {
        $identity = "$($entry.Path)`n$($entry.Name)"
        if (-not $existingValues.ContainsKey($identity)) {
            $backup.Values = @($backup.Values) + @($entry)
            $existingValues[$identity] = $true
            $updated = $true
        }
    }

    $existingKeys = @{}
    foreach ($entry in @($backup.Keys)) {
        $existingKeys[[string]$entry.Path] = $true
    }
    foreach ($entry in $KeySnapshots) {
        if (-not $existingKeys.ContainsKey([string]$entry.Path)) {
            $backup.Keys = @($backup.Keys) + @($entry)
            $existingKeys[[string]$entry.Path] = $true
            $updated = $true
        }
    }

    if ($created -or $updated) {
        $backup.UpdatedAtUtc = [DateTime]::UtcNow.ToString('o')
        Write-JsonAtomically -Value $backup -Path $Path
    }

    [pscustomobject]@{ Created = $created; Updated = ($updated -and -not $created); Backup = $backup }
}

function Restore-ValueSnapshots {
    param([Parameter(Mandatory = $true)][array]$Snapshots)

    foreach ($entry in $Snapshots) {
        if ([bool]$entry.Exists) {
            if (-not (Test-Path -LiteralPath $entry.Path)) {
                $null = New-Item -Path $entry.Path -Force
            }
            $null = New-ItemProperty -LiteralPath $entry.Path -Name $entry.Name -PropertyType $entry.Kind -Value $entry.Value -Force
        } elseif (Test-Path -LiteralPath $entry.Path) {
            Remove-ItemProperty -LiteralPath $entry.Path -Name $entry.Name -ErrorAction SilentlyContinue
        }
    }
}

function Remove-NewEmptyKeys {
    param([Parameter(Mandatory = $true)][array]$KeySnapshots)

    foreach ($entry in @($KeySnapshots | Sort-Object { $_.Path.Length } -Descending)) {
        if (-not [bool]$entry.Existed -and (Test-Path -LiteralPath $entry.Path)) {
            $key = Get-Item -LiteralPath $entry.Path
            if ($key.ValueCount -eq 0 -and $key.SubKeyCount -eq 0) {
                Remove-Item -LiteralPath $entry.Path
            }
        }
    }
}

function Test-SnapshotRestored {
    param([Parameter(Mandatory = $true)][array]$Snapshots)

    foreach ($entry in $Snapshots) {
        $current = Get-RegistryValueSnapshot -Path $entry.Path -Name $entry.Name
        if ([bool]$current.Exists -ne [bool]$entry.Exists) {
            return $false
        }
        if ([bool]$entry.Exists) {
            if ([string]$current.Kind -ne [string]$entry.Kind) {
                return $false
            }
            if ((ConvertTo-Json $current.Value -Compress) -ne (ConvertTo-Json $entry.Value -Compress)) {
                return $false
            }
        }
    }
    return $true
}

Assert-Windows
if ([string]::IsNullOrWhiteSpace($BackupPath)) {
    $BackupPath = Get-DefaultBackupPath
}

if ($Action -eq 'Audit') {
    $result = Get-AuditResult -SelectedMode $Mode -ResultAction 'Audited' -ResultBackupPath $BackupPath
    Write-Result -Result $result -Format $OutputFormat
    return
}

Assert-Administrator
$context = Get-MachineContext

if ($Action -eq 'Apply') {
    if ($Mode -eq 'ServerNotify' -and $context.ProductType -eq 1) {
        throw 'ServerNotify (AUOptions=7) is supported only on Windows Server 2016 and later.'
    }

    $management = Get-ManagementState -Context $context
    if (($context.DomainJoined -or $management.MdmUpdatePolicyPresent) -and -not $AllowManagedDevice) {
        throw 'This device appears domain-joined or MDM-managed. Re-run with -AllowManagedDevice only after checking the controlling policy source.'
    }
    if (@($management.MdmDeadlinePolicies).Count -gt 0) {
        throw 'MDM deadline policies are present and can override local restart behavior. Remove them at the management source.'
    }
    if (@($management.LocalDeadlinePolicies).Count -gt 0 -and -not $ClearConflictingDeadlinePolicies) {
        throw 'Local deadline policies can override restart behavior. Review them, then use -ClearConflictingDeadlinePolicies if removal is intended.'
    }

    $desired = @(Get-DesiredValues -SelectedMode $Mode)
    $valueSnapshots = @($desired | ForEach-Object {
        Get-RegistryValueSnapshot -Path $_.Path -Name $_.Name
    })
    $deadlineSnapshots = @()
    if ($ClearConflictingDeadlinePolicies) {
        $deadlineSnapshots = @($management.LocalDeadlinePolicies | ForEach-Object {
            Get-RegistryValueSnapshot -Path $_.Path -Name $_.Name
        })
    }
    $allSnapshots = @($valueSnapshots) + @($deadlineSnapshots)
    $keySnapshots = @(
        Get-KeySnapshot -Path $script:WindowsUpdatePath
        Get-KeySnapshot -Path $script:AutomaticUpdatesPath
    )

    if (-not $PSCmdlet.ShouldProcess($context.Hostname, "Apply Windows Update reboot-control mode $Mode")) {
        $result = Get-AuditResult -SelectedMode $Mode -ResultAction 'ApplyWhatIf' -ResultBackupPath $BackupPath
        Write-Result -Result $result -Format $OutputFormat
        return
    }

    $backupResult = Ensure-BaselineBackup -Context $context -ValueSnapshots $allSnapshots -KeySnapshots $keySnapshots -Path $BackupPath -SelectedMode $Mode
    try {
        if (-not (Test-Path -LiteralPath $script:WindowsUpdatePath)) {
            $null = New-Item -Path $script:WindowsUpdatePath -Force
        }
        if (-not (Test-Path -LiteralPath $script:AutomaticUpdatesPath)) {
            $null = New-Item -Path $script:AutomaticUpdatesPath -Force
        }
        foreach ($entry in $desired) {
            $null = New-ItemProperty -LiteralPath $entry.Path -Name $entry.Name -PropertyType DWord -Value ([int]$entry.Value) -Force
        }
        foreach ($entry in $deadlineSnapshots) {
            Remove-ItemProperty -LiteralPath $entry.Path -Name $entry.Name -ErrorAction Stop
        }

        $result = Get-AuditResult -SelectedMode $Mode -ResultAction 'Applied' -ResultBackupPath $BackupPath -BackupCreated $backupResult.Created -BackupUpdated $backupResult.Updated
        if (-not $result.Compliant) {
            throw 'Post-apply verification failed or a conflicting deadline policy remains.'
        }
        Write-Result -Result $result -Format $OutputFormat
    } catch {
        Restore-ValueSnapshots -Snapshots $allSnapshots
        Remove-NewEmptyKeys -KeySnapshots $keySnapshots
        throw
    }
    return
}

if (-not (Test-Path -LiteralPath $BackupPath)) {
    throw "No baseline backup exists at $BackupPath"
}
$backup = Get-Content -LiteralPath $BackupPath -Raw | ConvertFrom-Json
if ([int]$backup.SchemaVersion -ne 1) {
    throw "Unsupported backup schema in $BackupPath"
}
if ([string]$backup.MachineGuid -ne [string]$context.MachineGuid) {
    throw "Backup $BackupPath belongs to a different Windows installation."
}

$restoreValues = @($backup.Values)
$restoreKeys = @($backup.Keys)
$currentSnapshots = @($restoreValues | ForEach-Object {
    Get-RegistryValueSnapshot -Path $_.Path -Name $_.Name
})

if (-not $PSCmdlet.ShouldProcess($context.Hostname, "Restore Windows Update policy baseline from $BackupPath")) {
    $result = [pscustomobject][ordered]@{
        SchemaVersion = 1
        Action = 'RestoreWhatIf'
        Hostname = $context.Hostname
        BackupPath = $BackupPath
    }
    Write-Result -Result $result -Format $OutputFormat
    return
}

try {
    Restore-ValueSnapshots -Snapshots $restoreValues
    Remove-NewEmptyKeys -KeySnapshots $restoreKeys
    if (-not (Test-SnapshotRestored -Snapshots $restoreValues)) {
        throw 'Post-restore verification failed.'
    }
    $result = [pscustomobject][ordered]@{
        SchemaVersion = 1
        RestoredAtUtc = [DateTime]::UtcNow.ToString('o')
        Action = 'Restored'
        Hostname = $context.Hostname
        BackupPath = $BackupPath
        Verified = $true
        RebootPerformed = $false
        ServicesRestarted = @()
    }
    Write-Result -Result $result -Format $OutputFormat
} catch {
    Restore-ValueSnapshots -Snapshots $currentSnapshots
    throw
}
