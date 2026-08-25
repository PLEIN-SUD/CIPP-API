# Pester tests for the SOC ingestion path: resolving the tenant a notification names, and the
# secret that guards the public endpoint.
#
# Both carry a failure mode worse than not working: a case filed under the wrong client is never
# found again, and a public endpoint that creates records must never be open by accident. What is
# pinned here is that an ambiguous name resolves to nothing rather than to a guess, and that the
# absence of a secret shuts the door instead of opening it.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/PSIT/Resolve-PSITSocTenant.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/PSIT/Get-PSITSocWebhookSecret.ps1')

    function Get-CippTable { param($tablename) @{ Table = $tablename } }
    function Get-CIPPAzDataTableEntity { param($Table, $Filter) }
    function Add-CIPPAzDataTableEntity { param($Table, $Entity, [switch]$Force) }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $headers, $LogData) }

    $script:Tenants = @(
        [pscustomobject]@{ displayName = 'Contoso Manufacturing'; defaultDomainName = 'contoso.test'; customerId = 'cust-1' }
        [pscustomobject]@{ displayName = 'Contoso Retail'; defaultDomainName = 'contosoretail.test'; customerId = 'cust-2' }
        [pscustomobject]@{ displayName = 'Fabrikam'; defaultDomainName = 'fabrikam.test'; customerId = 'cust-3' }
    )
}

Describe 'Resolve-PSITSocTenant' {
    It 'matches the domain when the caller already knows it' {
        $Result = Resolve-PSITSocTenant -Name 'contoso.test' -Tenants $script:Tenants
        $Result.Tenant | Should -Be 'contoso.test'
        $Result.Method | Should -Be 'exact defaultDomainName'
    }

    It 'matches a display name regardless of case, accents and separators' {
        (Resolve-PSITSocTenant -Name 'FABRIKAM' -Tenants $script:Tenants).Tenant | Should -Be 'fabrikam.test'
        (Resolve-PSITSocTenant -Name 'contoso-manufacturing' -Tenants $script:Tenants).Tenant | Should -Be 'contoso.test'
    }

    It 'accepts a prefix only when a single client can match it' {
        $Result = Resolve-PSITSocTenant -Name 'Fabrik' -Tenants $script:Tenants
        $Result.Tenant | Should -Be 'fabrikam.test'
        $Result.Method | Should -Be 'displayName prefix'
    }

    It 'refuses to guess between two clients sharing a prefix' {
        $Result = Resolve-PSITSocTenant -Name 'Contoso' -Tenants $script:Tenants
        # A case filed under the wrong client is never found again: unmapped is the safe answer.
        $Result.Tenant | Should -Be 'unmapped'
        $Result.Method | Should -Be 'ambiguous displayName prefix'
    }

    It 'reports an unknown name as unmapped rather than falling back to anything' {
        (Resolve-PSITSocTenant -Name 'Someone Else' -Tenants $script:Tenants).Tenant | Should -Be 'unmapped'
        (Resolve-PSITSocTenant -Name '' -Tenants $script:Tenants).Tenant | Should -Be 'unmapped'
        (Resolve-PSITSocTenant -Name 'x' -Tenants @()).Tenant | Should -Be 'unmapped'
    }

    It 'says how it resolved, so the case can record it' {
        (Resolve-PSITSocTenant -Name 'cust-3' -Tenants $script:Tenants).Method | Should -Be 'exact customerId'
    }

    It 'separates a name nobody recognises from a name two clients answer to' {
        # The webhook branches on this and nothing else. A name matching nothing belongs, in
        # practice, to a client managed outside this portal: no case is opened for it, because a
        # case no screen here can investigate teaches the analyst to skip rows. A name matching
        # two clients is a managed client that needs disambiguating, and dropping it would lose a
        # real alert, so that one is filed under 'unmapped' for an analyst to reassign.
        (Resolve-PSITSocTenant -Name 'Someone Else' -Tenants $script:Tenants).Reason | Should -Be 'unknown'
        (Resolve-PSITSocTenant -Name 'Contoso' -Tenants $script:Tenants).Reason | Should -Be 'ambiguous'
        (Resolve-PSITSocTenant -Name 'cust-3' -Tenants $script:Tenants).Reason | Should -Be 'matched'
    }

    It 'treats an empty name and an empty tenant list as unknown, not as ambiguous' {
        (Resolve-PSITSocTenant -Name '' -Tenants $script:Tenants).Reason | Should -Be 'unknown'
        (Resolve-PSITSocTenant -Name 'x' -Tenants @()).Reason | Should -Be 'unknown'
    }
}

Describe 'the ingestion webhook secret' {
    BeforeEach {
        Mock -CommandName Write-LogMessage -MockWith { }
        Mock -CommandName Add-CIPPAzDataTableEntity -MockWith { }
    }

    It 'reports no secret when none was ever generated: the webhook then refuses everything' {
        Mock -CommandName Get-CIPPAzDataTableEntity -MockWith { $null }
        Get-PSITSocWebhookSecret | Should -BeNullOrEmpty
    }

    It 'reads back the stored secret with who rotated it and when' {
        Mock -CommandName Get-CIPPAzDataTableEntity -MockWith {
            [pscustomobject]@{ Secret = 'abc123'; RotatedUtc = '2026-08-24T10:00:00Z'; RotatedBy = 'analyste@example.test' }
        }
        $Secret = Get-PSITSocWebhookSecret
        $Secret.Secret | Should -Be 'abc123'
        $Secret.RotatedBy | Should -Be 'analyste@example.test'
    }

    It 'generates a secret long enough that guessing is not the threat model' {
        $Secret = Set-PSITSocWebhookSecret -Analyst 'analyste@example.test'
        $Secret.Secret.Length | Should -Be 64
        $Secret.RotatedBy | Should -Be 'analyste@example.test'
    }

    It 'never generates the same secret twice' {
        $First = Set-PSITSocWebhookSecret -Analyst 'a'
        $Second = Set-PSITSocWebhookSecret -Analyst 'a'
        $First.Secret | Should -Not -Be $Second.Secret
    }
}
