# Pester tests for the fleet health aggregation and its daily snapshot.
#
# Two things are worth pinning here. What counts as "protection in default" is a judgement the
# view, the history and any future alert all read from one place, so it is tested rather than
# trusted. And the snapshot keys on tenant and date: a timer that fires twice, or a node that
# retries, must not turn one bad day into two.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/PSIT/Get-PSITFleetHealth.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Entrypoints/Timer Functions/Start-PSITFleetHealthSnapshot.ps1')

    function Get-CIPPTable { param($tablename) @{ Table = $tablename } }
    function Add-CIPPAzDataTableEntity { param($Table, $Entity, [switch]$Force) }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $headers, $LogData) }
    function Get-CippException { param($Exception) @{ NormalizedError = $Exception.Exception.Message } }
    function Get-Tenants { param([switch]$IncludeErrors) }
    function New-GraphGetRequest { param($uri, $tenantid) }

    $script:Tenants = @(
        [pscustomobject]@{ customerId = 'cust-1'; defaultDomainName = 'contoso.test' }
        [pscustomobject]@{ customerId = 'cust-2'; defaultDomainName = 'fabrikam.test' }
    )

    $script:Protection = @(
        # Healthy.
        [pscustomobject]@{ tenantId = 'cust-1'; managedDeviceName = 'PC-001'; realTimeProtectionEnabled = $true; malwareProtectionEnabled = $true; attentionRequired = $false }
        # Real-time protection off.
        [pscustomobject]@{ tenantId = 'cust-1'; managedDeviceName = 'PC-002'; realTimeProtectionEnabled = $false; malwareProtectionEnabled = $true; attentionRequired = $false }
        # Protected, but carrying a threat.
        [pscustomobject]@{ tenantId = 'cust-2'; managedDeviceName = 'PC-101'; realTimeProtectionEnabled = $true; malwareProtectionEnabled = $true; attentionRequired = $false }
        # Protected, asking for attention.
        [pscustomobject]@{ tenantId = 'cust-2'; managedDeviceName = 'PC-102'; realTimeProtectionEnabled = $true; malwareProtectionEnabled = $true; attentionRequired = $true }
    )

    $script:Malware = @(
        [pscustomobject]@{ tenantId = 'cust-2'; managedDeviceName = 'PC-101'; malwareDisplayName = 'Wacatac'; malwareThreatState = 'Active' }
        # Remediated: not a reason to flag a machine today.
        [pscustomobject]@{ tenantId = 'cust-1'; managedDeviceName = 'PC-001'; malwareDisplayName = 'EICAR'; malwareThreatState = 'Remediated' }
    )
}

Describe 'Get-PSITFleetHealth' {
    It 'flags a machine whose protection is off, and leaves a healthy one alone' {
        $Health = Get-PSITFleetHealth -Protection $script:Protection -Malware $script:Malware -Tenants $script:Tenants

        $Healthy = $Health.Results | Where-Object { $_.DeviceName -eq 'PC-001' }
        $Healthy.ProtectionInDefault | Should -BeFalse
        $Healthy.NeedsAttention | Should -BeFalse

        $Off = $Health.Results | Where-Object { $_.DeviceName -eq 'PC-002' }
        $Off.ProtectionInDefault | Should -BeTrue
        $Off.NeedsAttention | Should -BeTrue
    }

    It 'carries the active threat on the machine running it, and ignores a remediated one' {
        $Health = Get-PSITFleetHealth -Protection $script:Protection -Malware $script:Malware -Tenants $script:Tenants

        $Threatened = $Health.Results | Where-Object { $_.DeviceName -eq 'PC-101' }
        $Threatened.ActiveThreatCount | Should -Be 1
        $Threatened.ActiveThreats | Should -Contain 'Wacatac'
        # Protection is on: the threat alone is what makes it worth looking at.
        $Threatened.ProtectionInDefault | Should -BeFalse
        $Threatened.NeedsAttention | Should -BeTrue

        # A remediated detection is history, not a reason to flag the machine today.
        ($Health.Results | Where-Object { $_.DeviceName -eq 'PC-001' }).ActiveThreatCount | Should -Be 0
    }

    It 'treats attentionRequired as worth looking at even when protection is on' {
        $Health = Get-PSITFleetHealth -Protection $script:Protection -Malware $script:Malware -Tenants $script:Tenants
        ($Health.Results | Where-Object { $_.DeviceName -eq 'PC-102' }).NeedsAttention | Should -BeTrue
    }

    It 'resolves the tenant name, and falls back to the id rather than showing nothing' {
        $Health = Get-PSITFleetHealth -Protection $script:Protection -Malware $script:Malware -Tenants $script:Tenants
        ($Health.Results | Where-Object { $_.DeviceName -eq 'PC-001' }).Tenant | Should -Be 'contoso.test'

        $Unknown = Get-PSITFleetHealth -Protection @(
            [pscustomobject]@{ tenantId = 'cust-unknown'; managedDeviceName = 'PC-X'; realTimeProtectionEnabled = $true; malwareProtectionEnabled = $true }
        ) -Malware @() -Tenants $script:Tenants
        $Unknown.Results[0].Tenant | Should -Be 'cust-unknown'
    }

    It 'counts machines reported per tenant, which is what makes a silent fleet visible' {
        $Health = Get-PSITFleetHealth -Protection $script:Protection -Malware $script:Malware -Tenants $script:Tenants

        $Contoso = $Health.Tenants | Where-Object { $_.Tenant -eq 'contoso.test' }
        $Contoso.DevicesReported | Should -Be 2
        $Contoso.NeedsAttention | Should -Be 1
        $Contoso.ProtectionInDefault | Should -Be 1
        $Contoso.ActiveThreats | Should -Be 0

        $Fabrikam = $Health.Tenants | Where-Object { $_.Tenant -eq 'fabrikam.test' }
        $Fabrikam.DevicesReported | Should -Be 2
        $Fabrikam.NeedsAttention | Should -Be 2
        $Fabrikam.ActiveThreats | Should -Be 1
    }

    It 'answers with empty counts rather than throwing when nothing is reported' {
        $Health = Get-PSITFleetHealth -Protection @() -Malware @() -Tenants $script:Tenants
        $Health.Metadata.TotalDevices | Should -Be 0
        @($Health.Tenants).Count | Should -Be 0
    }
}

Describe 'Start-PSITFleetHealthSnapshot' {
    BeforeEach {
        $script:Written = [System.Collections.Generic.List[object]]::new()
        Mock -CommandName Write-LogMessage -MockWith { }
        Mock -CommandName Add-CIPPAzDataTableEntity -MockWith { $script:Written.Add($Entity) }
        Mock -CommandName Get-PSITFleetHealth -MockWith {
            [pscustomobject]@{
                Results  = @()
                Tenants  = @(
                    [pscustomobject]@{ Tenant = 'contoso.test'; DevicesReported = 12; NeedsAttention = 2; ProtectionInDefault = 1; ActiveThreats = 1 }
                    [pscustomobject]@{ Tenant = 'fabrikam.test'; DevicesReported = 30; NeedsAttention = 0; ProtectionInDefault = 0; ActiveThreats = 0 }
                )
                Metadata = [pscustomobject]@{ TotalDevices = 42; NeedsAttention = 2 }
            }
        }
    }

    It 'writes one row per tenant, keyed by day so a re-run replaces rather than doubles' {
        Start-PSITFleetHealthSnapshot -Confirm:$false

        $script:Written.Count | Should -Be 2
        $Today = [datetime]::UtcNow.ToString('yyyy-MM-dd')
        foreach ($Entity in $script:Written) {
            $Entity.RowKey | Should -Be $Today
        }
        ($script:Written | Where-Object { $_.PartitionKey -eq 'contoso.test' }).NeedsAttention | Should -Be 2
        ($script:Written | Where-Object { $_.PartitionKey -eq 'fabrikam.test' }).DevicesReported | Should -Be 30
    }

    It 'records a healthy tenant too: a trend needs the good days to show a bad one' {
        Start-PSITFleetHealthSnapshot -Confirm:$false
        ($script:Written | Where-Object { $_.PartitionKey -eq 'fabrikam.test' }).NeedsAttention | Should -Be 0
    }

    It 'writes nothing and does not throw when the read fails' {
        Mock -CommandName Get-PSITFleetHealth -MockWith { throw 'Forbidden' }
        { Start-PSITFleetHealthSnapshot -Confirm:$false } | Should -Not -Throw
        $script:Written.Count | Should -Be 0
    }

    It 'keeps recording the other tenants when one row cannot be written' {
        # One client failing must not cost the others their history for the day.
        Mock -CommandName Add-CIPPAzDataTableEntity -MockWith {
            if ($Entity.PartitionKey -eq 'contoso.test') { throw 'Table unavailable' }
            $script:Written.Add($Entity)
        }
        { Start-PSITFleetHealthSnapshot -Confirm:$false } | Should -Not -Throw
        $script:Written.Count | Should -Be 1
        $script:Written[0].PartitionKey | Should -Be 'fabrikam.test'
    }
}
