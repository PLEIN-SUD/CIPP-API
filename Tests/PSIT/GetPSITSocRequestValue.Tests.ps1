# Pester tests for the autocomplete unwrapper.
#
# Written after a real failure: adopting a Defender incident sent Severity as
# @{value=P3; label=P3}, which a ValidateSet rejected loudly - and TypeId as the same shape,
# which a loose regex simply failed to match, so the case would have been created with no type
# and therefore no investigation guide. The loud failure was the lucky one.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/PSIT/Get-PSITSocRequestValue.ps1')
}

Describe 'Get-PSITSocRequestValue' {
    It 'unwraps what the autocomplete submits' {
        Get-PSITSocRequestValue -Value ([pscustomobject]@{ value = 'P3'; label = 'P3' }) | Should -Be 'P3'
    }

    It 'unwraps a numeric selection, which is the one that failed silently' {
        # TypeId arrives as an int inside the option: read raw, it never matched the digit check
        # and the case was created with no type at all.
        $Value = Get-PSITSocRequestValue -Value ([pscustomobject]@{ value = 13; label = '13 - Malware' })
        $Value | Should -Be 13
        "$Value" | Should -Match '^\d+$'
    }

    It 'passes a plain value through untouched, which is what the webhook sends' {
        Get-PSITSocRequestValue -Value 'contoso.test' | Should -Be 'contoso.test'
        Get-PSITSocRequestValue -Value 13 | Should -Be 13
        Get-PSITSocRequestValue -Value $true | Should -BeTrue
    }

    It 'unwraps every entry of a multi-select, and keeps it a list' {
        $Result = @(Get-PSITSocRequestValue -Value @(
                [pscustomobject]@{ value = 'a@contoso.test'; label = 'A' }
                [pscustomobject]@{ value = 'b@contoso.test'; label = 'B' }
            ))
        $Result.Count | Should -Be 2
        $Result[0] | Should -Be 'a@contoso.test'
    }

    It 'leaves a plain list alone' {
        $Result = @(Get-PSITSocRequestValue -Value @('a@contoso.test', 'b@contoso.test'))
        $Result | Should -Be @('a@contoso.test', 'b@contoso.test')
    }

    It 'returns null for null rather than inventing a value' {
        Get-PSITSocRequestValue -Value $null | Should -BeNullOrEmpty
    }

    It 'returns an object with no value property as it is, instead of dropping it' {
        # Entities is an object the case stores whole: unwrapping must not eat it.
        $Entities = [pscustomobject]@{ upn = 'a@contoso.test'; deviceName = 'PC-042' }
        (Get-PSITSocRequestValue -Value $Entities).upn | Should -Be 'a@contoso.test'
    }
}
