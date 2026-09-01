# Pester tests for the AbuseIPDB reputation read.
#
# The chips sit next to every address on the SOC screens, so what is pinned here is quota and
# custody discipline: the cache answers before the API is spent, private addresses never leave
# the building, a failed lookup degrades to the dated stale row rather than to a fabricated
# zero, and no key means a note - not an error, and not silence.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/PSIT/Get-PSITIpReputation.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/PSIT/Get-PSITIpReputationKey.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/PSIT/Set-PSITIpReputationKey.ps1')

    function Get-CippTable { param($tablename) @{ Table = $tablename } }
    function Get-CIPPAzDataTableEntity { param($Table, $Filter) }
    function Add-CIPPAzDataTableEntity { param($Table, $Entity, [switch]$Force) }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $headers, $LogData) }
    function Invoke-RestMethod { param($Method, $Uri, $Headers) }

    $script:FreshUtc = (Get-Date).ToUniversalTime().AddHours(-1).ToString('o')
    $script:StaleUtc = (Get-Date).ToUniversalTime().AddDays(-3).ToString('o')
}

Describe 'Get-PSITIpReputation' {
    BeforeEach {
        Mock -CommandName Write-LogMessage -MockWith { }
        Mock -CommandName Add-CIPPAzDataTableEntity -MockWith { }
        Mock -CommandName Get-CIPPAzDataTableEntity -MockWith { $null }
        Mock -CommandName Get-PSITIpReputationKey -MockWith { [pscustomobject]@{ Key = 'k' } }
        Mock -CommandName Invoke-RestMethod -MockWith {
            [pscustomobject]@{ data = [pscustomobject]@{
                    abuseConfidenceScore = 87; totalReports = 23; countryCode = 'RU'
                    isp = 'Example Hosting'; usageType = 'Data Center/Web Hosting/Transit'
                    isTor = $false; domain = 'example.net'
                } }
        }
    }

    It 'never sends a private or invalid address to the third party' {
        $Answer = Get-PSITIpReputation -Ips @('10.0.0.4', '192.168.1.10', '172.20.3.1', 'not-an-ip', '127.0.0.1', 'fe80::1')

        $Answer.Rows | Should -HaveCount 0
        Should -Invoke Invoke-RestMethod -Times 0
        Should -Invoke Get-CIPPAzDataTableEntity -Times 0
    }

    It 'answers from the fresh cache without spending the quota' {
        Mock -CommandName Get-CIPPAzDataTableEntity -MockWith {
            [pscustomobject]@{ RowKey = '203.0.113.9'; Score = '12'; Reports = '2'; Country = 'FR'; Isp = 'x'; UsageType = 'isp'; IsTor = 'False'; CheckedUtc = $script:FreshUtc }
        }

        $Answer = Get-PSITIpReputation -Ips @('203.0.113.9')

        $Answer.Rows[0].Score | Should -Be 12
        $Answer.Rows[0].Stale | Should -BeFalse
        Should -Invoke Invoke-RestMethod -Times 0
    }

    It 'refreshes a stale row through the API and stores the dated answer' {
        Mock -CommandName Get-CIPPAzDataTableEntity -MockWith {
            [pscustomobject]@{ RowKey = '203.0.113.9'; Score = '5'; Reports = '1'; Country = 'FR'; Isp = 'x'; UsageType = 'isp'; IsTor = 'False'; CheckedUtc = $script:StaleUtc }
        }

        $Answer = Get-PSITIpReputation -Ips @('203.0.113.9')

        Should -Invoke Invoke-RestMethod -Times 1
        Should -Invoke Add-CIPPAzDataTableEntity -Times 1 -ParameterFilter { $Entity.Score -eq '87' }
        $Answer.Rows[0].Score | Should -Be 87
        $Answer.Rows[0].Reports | Should -Be 23
    }

    It 'degrades a failed lookup to the dated stale row, never to a fabricated zero' {
        Mock -CommandName Get-CIPPAzDataTableEntity -MockWith {
            [pscustomobject]@{ RowKey = '203.0.113.9'; Score = '55'; Reports = '9'; Country = 'FR'; Isp = 'x'; UsageType = 'isp'; IsTor = 'False'; CheckedUtc = $script:StaleUtc }
        }
        Mock -CommandName Invoke-RestMethod -MockWith { throw 'quota exceeded' }

        $Answer = Get-PSITIpReputation -Ips @('203.0.113.9')

        $Answer.Rows[0].Score | Should -Be 55
        $Answer.Rows[0].Stale | Should -BeTrue
        $Answer.Notes[0] | Should -Match 'en échec'
    }

    It 'says when no key is configured, and still serves the local memory' {
        Mock -CommandName Get-PSITIpReputationKey -MockWith { $null }
        # Only one of the two addresses has a memory: the other must answer nothing.
        Mock -CommandName Get-CIPPAzDataTableEntity -MockWith {
            if ($Filter -match '203\.0\.113\.9') {
                [pscustomobject]@{ RowKey = '203.0.113.9'; Score = '55'; Reports = '9'; Country = 'FR'; Isp = 'x'; UsageType = 'isp'; IsTor = 'False'; CheckedUtc = $script:StaleUtc }
            }
        }

        $Answer = Get-PSITIpReputation -Ips @('203.0.113.9', '198.51.100.4')

        Should -Invoke Invoke-RestMethod -Times 0
        $Answer.Rows | Should -HaveCount 1
        $Answer.Notes[-1] | Should -Match 'Aucune clé'
    }

    It 'caps a batch at twenty addresses' {
        $Many = @(1..30 | ForEach-Object { "203.0.113.$_" })

        $null = Get-PSITIpReputation -Ips $Many

        Should -Invoke Invoke-RestMethod -Times 20 -Exactly
    }
}

Describe 'Set-PSITIpReputationKey' {
    BeforeEach {
        Mock -CommandName Write-LogMessage -MockWith { }
        Mock -CommandName Add-CIPPAzDataTableEntity -MockWith { }
        Mock -CommandName Invoke-RestMethod -MockWith { [pscustomobject]@{ data = @{} } }
    }

    It 'validates the key with one live check before storing it' {
        $Outcome = Set-PSITIpReputationKey -Key 'abc' -Analyst 'a@example.test'

        Should -Invoke Invoke-RestMethod -Times 1
        Should -Invoke Add-CIPPAzDataTableEntity -Times 1 -ParameterFilter { $Entity.Key -eq 'abc' }
        $Outcome.Configured | Should -BeTrue
    }

    It 'refuses a key the service rejects, and stores nothing' {
        Mock -CommandName Invoke-RestMethod -MockWith { throw '401' }

        { Set-PSITIpReputationKey -Key 'bad' -Analyst 'a@example.test' } |
            Should -Throw "*n'a pas été acceptée*"
        Should -Invoke Add-CIPPAzDataTableEntity -Times 0
    }

    It 'clears on an empty key, without calling the service' {
        $Outcome = Set-PSITIpReputationKey -Key '' -Analyst 'a@example.test'

        Should -Invoke Invoke-RestMethod -Times 0
        Should -Invoke Add-CIPPAzDataTableEntity -Times 1 -ParameterFilter { $Entity.Key -eq '' }
        $Outcome.Configured | Should -BeFalse
    }
}
