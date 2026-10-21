BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot '..\WindowsUpdateRebootControl.ps1'
}

Describe 'WindowsUpdateRebootControl syntax' {
    It 'parses without PowerShell syntax errors' {
        $tokens = $null
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile(
            $scriptPath,
            [ref]$tokens,
            [ref]$errors
        )
        $errors | Should -BeNullOrEmpty
    }
}

Describe 'WindowsUpdateRebootControl audit' {
    It 'audits <Mode> without changing the machine' -ForEach @(
        @{ Mode = 'StrictManual'; ExpectedNoAutoUpdate = 1; ExpectedAUOptions = 2 },
        @{ Mode = 'ClientNotify'; ExpectedNoAutoUpdate = 0; ExpectedAUOptions = 2 },
        @{ Mode = 'ServerNotify'; ExpectedNoAutoUpdate = 0; ExpectedAUOptions = 7 }
    ) {
        $result = & $scriptPath -Action Audit -Mode $Mode -OutputFormat Object

        $result.Action | Should -Be 'Audited'
        $result.Mode | Should -Be $Mode
        ($result.PolicyValues | Where-Object Name -eq 'NoAutoUpdate').ExpectedValue |
            Should -Be $ExpectedNoAutoUpdate
        ($result.PolicyValues | Where-Object Name -eq 'AUOptions').ExpectedValue |
            Should -Be $ExpectedAUOptions
    }

    It 'can emit machine-readable JSON explicitly' {
        $json = & $scriptPath -Action Audit -Mode StrictManual -OutputFormat Json
        $result = $json | ConvertFrom-Json

        $result.Action | Should -Be 'Audited'
        $result.Mode | Should -Be 'StrictManual'
        $result.PolicyValues.Count | Should -Be 4
    }
}
