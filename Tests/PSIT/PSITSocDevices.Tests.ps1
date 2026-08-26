# Pester tests for the merged device list.
#
# The picker read Intune alone, which made MDE-only machines unselectable and therefore
# uninvestigable. What is pinned here: the join on the Entra device id, the ManagedBy column an
# analyst learns capabilities from, and the refusal to fail silently on one side - a list quietly
# missing Defender would hide MDE-only machines exactly the way the old picker did.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/PSIT/Get-PSITSocDevices.ps1')

    function New-GraphGetRequest { param($uri, $tenantid, $scope) }

    $script:Intune = @(
        [pscustomobject]@{ id = 'int-1'; deviceName = 'PC-001'; azureADDeviceId = 'AAD-1'; userPrincipalName = 'a@contoso.test'; operatingSystem = 'Windows'; lastSyncDateTime = '2026-08-26T06:00:00Z' }
        [pscustomobject]@{ id = 'int-2'; deviceName = 'IPHONE-A'; azureADDeviceId = 'aad-2'; userPrincipalName = 'b@contoso.test'; operatingSystem = 'iOS'; lastSyncDateTime = '2026-08-25T06:00:00Z' }
    )
    $script:Mde = @(
        [pscustomobject]@{ id = 'mde-1'; computerDnsName = 'pc-001.contoso.test'; aadDeviceId = 'aad-1'; onboardingStatus = 'Onboarded'; osPlatform = 'Windows11'; lastSeen = '2026-08-26T08:00:00Z' }
        [pscustomobject]@{ id = 'mde-9'; computerDnsName = 'srv-legacy'; aadDeviceId = $null; onboardingStatus = 'Onboarded'; osPlatform = 'WindowsServer2019'; lastSeen = '2026-08-26T07:00:00Z' }
    )
}

Describe 'Get-PSITSocDevices' {
    It 'joins the two worlds on the Entra device id, case-insensitively' {
        $Result = Get-PSITSocDevices -TenantFilter 'contoso.test' -IntuneDevices $script:Intune -MdeMachines $script:Mde

        $Joined = $Result.Results | Where-Object { $_.DeviceName -eq 'PC-001' }
        $Joined.ManagedBy | Should -Be 'Intune + MDE'
        $Joined.IntuneId | Should -Be 'int-1'
        $Joined.MdeId | Should -Be 'mde-1'
        # The freshest sighting of the two.
        $Joined.LastSeen | Should -Be '2026-08-26T08:00:00Z'
    }

    It 'keeps the machine only Defender knows, which is the reason this list exists' {
        $Result = Get-PSITSocDevices -TenantFilter 'contoso.test' -IntuneDevices $script:Intune -MdeMachines $script:Mde

        $Server = $Result.Results | Where-Object { $_.DeviceName -eq 'srv-legacy' }
        $Server.ManagedBy | Should -Be 'MDE'
        $Server.IntuneId | Should -Be ''
        $Server.OnboardingStatus | Should -Be 'Onboarded'
    }

    It 'keeps the machine only Intune knows' {
        $Result = Get-PSITSocDevices -TenantFilter 'contoso.test' -IntuneDevices $script:Intune -MdeMachines $script:Mde
        ($Result.Results | Where-Object { $_.DeviceName -eq 'IPHONE-A' }).ManagedBy | Should -Be 'Intune'
    }

    It 'answers with the readable side and names the failed one, never silently' {
        Mock -CommandName New-GraphGetRequest -MockWith {
            if ($uri -like '*securitycenter*') { throw '403 Forbidden' }
            return $script:Intune
        }

        $Result = Get-PSITSocDevices -TenantFilter 'contoso.test'
        @($Result.Results).Count | Should -Be 2
        $Result.Metadata.MdeRead | Should -BeFalse
        @($Result.Metadata.Warnings)[0] | Should -Match 'Defender for Endpoint unreadable'
    }

    It 'throws when neither side can be read: an empty list would look like an empty tenant' {
        Mock -CommandName New-GraphGetRequest -MockWith { throw 'down' }
        { Get-PSITSocDevices -TenantFilter 'contoso.test' } | Should -Throw '*Neither Intune nor Defender*'
    }
}
