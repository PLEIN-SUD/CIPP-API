# Pester tests for the fleet health read and its daily snapshot.
#
# The source changed after production proved the Lighthouse managed-tenant aggregates are refused
# on this tenancy: the data now comes from Intune's managed devices, one tenant at a time. What is
# pinned here is what survived that change. "Protection in default" is a judgement the view, the
# history and any future alert read from one place, so it is tested rather than trusted. Machines
# Intune knows but that report no protection state are counted rather than dropped, because an
# absence must never render as a healthy row. And the snapshot keys on tenant and date: a timer
# that fires twice, or a node that retries, must not turn one bad day into two.

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

    $script:Device = {
        param($Name, $Protection)
        [pscustomobject]@{
            id                     = "id-$Name"
            deviceName             = $Name
            operatingSystem        = 'Windows'
            osVersion              = '10.0.22631.4460'
            lastSyncDateTime       = '2026-08-25T05:00:00Z'
            windowsProtectionState = $Protection
        }
    }

    $script:Devices = @(
        # Healthy.
        & $script:Device 'PC-001' ([pscustomobject]@{ realTimeProtectionEnabled = $true; malwareProtectionEnabled = $true; attentionRequired = $false; signatureUpdateOverdue = $false })
        # Real-time protection off.
        & $script:Device 'PC-002' ([pscustomobject]@{ realTimeProtectionEnabled = $false; malwareProtectionEnabled = $true; attentionRequired = $false; signatureUpdateOverdue = $false })
        # Protected, signatures behind.
        & $script:Device 'PC-003' ([pscustomobject]@{ realTimeProtectionEnabled = $true; malwareProtectionEnabled = $true; attentionRequired = $false; signatureUpdateOverdue = $true })
        # Protected and up to date, but asking for attention.
        & $script:Device 'PC-004' ([pscustomobject]@{ realTimeProtectionEnabled = $true; malwareProtectionEnabled = $true; attentionRequired = $true; signatureUpdateOverdue = $false })
        # Known to Intune, reports no protection state at all.
        & $script:Device 'MAC-001' $null
    )
}

Describe 'Get-PSITFleetHealth' {
    It 'flags a machine whose protection is off, and leaves a healthy one alone' {
        $Result = Get-PSITFleetHealth -TenantFilter 'contoso.test' -Devices $script:Devices

        $Off = $Result.Results | Where-Object { $_.DeviceName -eq 'PC-002' }
        $Off.ProtectionInDefault | Should -BeTrue
        $Off.NeedsAttention | Should -BeTrue

        $Healthy = $Result.Results | Where-Object { $_.DeviceName -eq 'PC-001' }
        $Healthy.ProtectionInDefault | Should -BeFalse
        $Healthy.NeedsAttention | Should -BeFalse
    }

    It 'treats signatures behind as worth looking at, without calling the protection broken' {
        $Result = Get-PSITFleetHealth -TenantFilter 'contoso.test' -Devices $script:Devices

        $Overdue = $Result.Results | Where-Object { $_.DeviceName -eq 'PC-003' }
        $Overdue.SignatureUpdateOverdue | Should -BeTrue
        $Overdue.NeedsAttention | Should -BeTrue
        # Two distinct problems, two distinct counters: an out-of-date signature is not a
        # disabled antivirus, and merging them would overstate the second.
        $Overdue.ProtectionInDefault | Should -BeFalse
    }

    It 'treats attentionRequired as worth looking at even when protection is on' {
        $Result = Get-PSITFleetHealth -TenantFilter 'contoso.test' -Devices $script:Devices

        $Attention = $Result.Results | Where-Object { $_.DeviceName -eq 'PC-004' }
        $Attention.NeedsAttention | Should -BeTrue
        $Attention.ProtectionInDefault | Should -BeFalse
    }

    It 'counts machines with no protection state instead of passing them off as healthy' {
        # A Mac, or a Windows machine that has never reported: excluded from the protection
        # figures, but reported as excluded. Silently dropping it would shrink the denominator
        # and make the fleet look better than it is.
        $Result = Get-PSITFleetHealth -TenantFilter 'contoso.test' -Devices $script:Devices

        @($Result.Results | Where-Object { $_.DeviceName -eq 'MAC-001' }).Count | Should -Be 0
        $Result.Tenant.WithoutProtectionState | Should -Be 1
        $Result.Tenant.DevicesReported | Should -Be 4
    }

    It 'counts the tenant figures the snapshot and the view both read' {
        $Result = Get-PSITFleetHealth -TenantFilter 'contoso.test' -Devices $script:Devices

        $Result.Tenant.Tenant | Should -Be 'contoso.test'
        $Result.Tenant.NeedsAttention | Should -Be 3
        $Result.Tenant.ProtectionInDefault | Should -Be 1
        $Result.Tenant.SignatureOverdue | Should -Be 1
    }

    It 'refuses AllTenants rather than quietly reading one tenant' {
        # The fleet-wide view is assembled from snapshots. A whole-fleet read reaching this
        # function means a caller got the routing wrong, and answering for one tenant would look
        # like an answer for forty.
        { Get-PSITFleetHealth -TenantFilter 'AllTenants' } | Should -Throw -ExpectedMessage '*one tenant at a time*'
    }

    It 'names the tenant and repeats what Graph said when the read fails' {
        Mock -CommandName New-GraphGetRequest -MockWith { throw 'Forbidden. Access denied.' }

        { Get-PSITFleetHealth -TenantFilter 'contoso.test' } |
            Should -Throw -ExpectedMessage '*contoso.test*Forbidden. Access denied.*'
    }

    It 'answers with empty counts rather than throwing when nothing is reported' {
        $Result = Get-PSITFleetHealth -TenantFilter 'contoso.test' -Devices @()

        @($Result.Results).Count | Should -Be 0
        $Result.Tenant.DevicesReported | Should -Be 0
        $Result.Metadata.TotalDevices | Should -Be 0
    }
}

Describe 'Start-PSITFleetHealthSnapshot' {
    BeforeEach {
        $script:Written = [System.Collections.Generic.List[object]]::new()
        Mock -CommandName Add-CIPPAzDataTableEntity -MockWith { $script:Written.Add($Entity) }
        Mock -CommandName Get-Tenants -MockWith {
            @(
                [pscustomobject]@{ defaultDomainName = 'contoso.test' }
                [pscustomobject]@{ defaultDomainName = 'fabrikam.test' }
            )
        }
        Mock -CommandName Get-PSITFleetHealth -MockWith {
            Get-PSITFleetHealth -TenantFilter $TenantFilter -Devices $script:Devices
        } -ParameterFilter { $null -eq $Devices }
    }

    It 'writes one row per tenant, keyed by day so a re-run replaces rather than doubles' {
        Start-PSITFleetHealthSnapshot -Confirm:$false

        $script:Written.Count | Should -Be 2
        @($script:Written.PartitionKey | Sort-Object) | Should -Be @('contoso.test', 'fabrikam.test')
        @($script:Written.RowKey | Select-Object -Unique).Count | Should -Be 1
        $script:Written[0].RowKey | Should -Be ([datetime]::UtcNow.ToString('yyyy-MM-dd'))
    }

    It 'stores the machines worth looking at, which is what the fleet view reads' {
        Start-PSITFleetHealthSnapshot -Confirm:$false

        $Stored = @($script:Written[0].AttentionDevices | ConvertFrom-Json)
        @($Stored.DeviceName | Sort-Object) | Should -Be @('PC-002', 'PC-003', 'PC-004')
        $script:Written[0].AttentionTruncated | Should -BeFalse
        # The healthy machine is not stored: the row carries the counts for everyone and the
        # detail only for what needs doing.
        $Stored.DeviceName | Should -Not -Contain 'PC-001'
    }

    It 'flags a truncated list rather than presenting it as complete' {
        $Many = 1..150 | ForEach-Object {
            & $script:Device "PC-$_" ([pscustomobject]@{ realTimeProtectionEnabled = $false; malwareProtectionEnabled = $true; attentionRequired = $false; signatureUpdateOverdue = $false })
        }
        Mock -CommandName Get-PSITFleetHealth -MockWith {
            Get-PSITFleetHealth -TenantFilter $TenantFilter -Devices $Many
        } -ParameterFilter { $null -eq $Devices }

        Start-PSITFleetHealthSnapshot -Confirm:$false

        @($script:Written[0].AttentionDevices | ConvertFrom-Json).Count | Should -Be 100
        $script:Written[0].AttentionTruncated | Should -BeTrue
        # The count is not truncated with the list: the row still says 150 need attention.
        $script:Written[0].NeedsAttention | Should -Be 150
    }

    It 'records a healthy tenant too: a trend needs the good days to show a bad one' {
        $Healthy = @(& $script:Device 'PC-001' ([pscustomobject]@{ realTimeProtectionEnabled = $true; malwareProtectionEnabled = $true; attentionRequired = $false; signatureUpdateOverdue = $false }))
        Mock -CommandName Get-PSITFleetHealth -MockWith {
            Get-PSITFleetHealth -TenantFilter $TenantFilter -Devices $Healthy
        } -ParameterFilter { $null -eq $Devices }

        Start-PSITFleetHealthSnapshot -Confirm:$false

        $script:Written.Count | Should -Be 2
        $script:Written[0].NeedsAttention | Should -Be 0
        $script:Written[0].DevicesReported | Should -Be 1
    }

    It 'keeps recording the other tenants when one fails to read' {
        # One client refusing the read must not cost the other thirty-nine their history.
        Mock -CommandName Get-PSITFleetHealth -MockWith {
            if ($TenantFilter -eq 'contoso.test') { throw 'Forbidden. Access denied.' }
            Get-PSITFleetHealth -TenantFilter $TenantFilter -Devices $script:Devices
        } -ParameterFilter { $null -eq $Devices }

        Start-PSITFleetHealthSnapshot -Confirm:$false

        $script:Written.Count | Should -Be 1
        $script:Written[0].PartitionKey | Should -Be 'fabrikam.test'
    }

    It 'keeps recording the other tenants when one row cannot be written' {
        Mock -CommandName Add-CIPPAzDataTableEntity -MockWith {
            if ($Entity.PartitionKey -eq 'contoso.test') { throw 'Table storage unavailable' }
            $script:Written.Add($Entity)
        }

        Start-PSITFleetHealthSnapshot -Confirm:$false

        $script:Written.Count | Should -Be 1
        $script:Written[0].PartitionKey | Should -Be 'fabrikam.test'
    }
}

Describe 'Get-PSITFleetHealth with Defender machines' {
    # A server onboarded by script never appears in Intune, and a fleet view that misses it calls
    # an unmanaged machine healthy. What is pinned: the MDE-only row exists, its Intune readings
    # are null rather than false, and a Defender side that cannot be read is named, never silent.

    BeforeAll {
        $script:Mde = @(
            # Joined to PC-001 through the Entra id.
            [pscustomobject]@{ id = 'mde-1'; computerDnsName = 'pc-001.contoso.test'; aadDeviceId = 'AAD-1'; healthStatus = 'Active'; riskScore = 'High'; osPlatform = 'Windows11'; lastSeen = '2026-08-27T07:00:00Z' }
            # Known to Defender alone.
            [pscustomobject]@{ id = 'mde-9'; computerDnsName = 'srv-legacy'; aadDeviceId = $null; healthStatus = 'Inactive'; riskScore = 'None'; osPlatform = 'WindowsServer2019'; lastSeen = '2026-08-20T07:00:00Z' }
        )
        $script:IntuneWithAad = @($script:Devices | Where-Object { $_.windowsProtectionState } | ForEach-Object {
                $_ | Select-Object *, @{ n = 'azureADDeviceId'; e = { if ($_.deviceName -eq 'PC-001') { 'aad-1' } else { '' } } }
            })
    }

    It 'appends the machine only Defender knows, with null Intune readings rather than false' {
        $Result = Get-PSITFleetHealth -TenantFilter 'contoso.test' -Devices $script:IntuneWithAad -MdeMachines $script:Mde

        $Server = $Result.Results | Where-Object { $_.DeviceName -eq 'srv-legacy' }
        $Server.ManagedBy | Should -Be 'MDE'
        # Null is "not readable here"; false would claim the protection is off.
        $Server.ProtectionInDefault | Should -BeNullOrEmpty
        # Inactive in Defender is a machine that stopped reporting: attention, said with its reason.
        $Server.NeedsAttention | Should -BeTrue
        $Result.Tenant.MdeOnly | Should -Be 1
    }

    It 'marks the joined machine and lifts a High risk score into attention' {
        $Result = Get-PSITFleetHealth -TenantFilter 'contoso.test' -Devices $script:IntuneWithAad -MdeMachines $script:Mde

        $Joined = $Result.Results | Where-Object { $_.DeviceName -eq 'PC-001' }
        $Joined.ManagedBy | Should -Be 'Intune + MDE'
        $Joined.RiskScore | Should -Be 'High'
        # Healthy in Intune, High risk in Defender: the second wins the attention flag.
        $Joined.NeedsAttention | Should -BeTrue
    }

    It 'names an unreadable Defender side instead of quietly showing Intune alone' {
        Mock -CommandName New-GraphGetRequest -MockWith {
            if ($uri -like '*securitycenter*') { throw '403 Forbidden' }
            return $script:IntuneWithAad
        }

        $Result = Get-PSITFleetHealth -TenantFilter 'contoso.test'
        @($Result.Metadata.Warnings)[0] | Should -Match 'Defender for Endpoint unreadable'
        # The Intune rows still answer: one side down does not empty the fleet.
        @($Result.Results).Count | Should -BeGreaterThan 0
    }
}
