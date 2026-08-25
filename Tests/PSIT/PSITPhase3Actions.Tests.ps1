# Pester tests for the two containment actions of the machine and mail sides: Defender for
# Endpoint isolation, and the soft delete of a delivered malicious message.
#
# Both act on production tenants, so what is pinned here is what makes them safe: full isolation
# rather than the selective variant that still lets mail through, soft delete rather than a purge
# nobody can undo, a refusal to act when the target cannot be identified, and an error that says
# what happened instead of an empty result that reads like "nothing to do".

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/PSIT/Set-PSITMdeIsolation.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/PSIT/Invoke-PSITMailRemediation.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/PSIT/Get-PSITMailEvidence.ps1')

    function New-GraphGetRequest { param($uri, $tenantid, $scope, $AsApp) }
    function New-GraphPOSTRequest { param($uri, $tenantid, $body, $scope, $AsApp, $type) }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $headers, $LogData) }
}

Describe 'Set-PSITMdeIsolation' {
    BeforeEach {
        $script:Posts = [System.Collections.Generic.List[object]]::new()
        Mock -CommandName Write-LogMessage -MockWith { }
        Mock -CommandName New-GraphGetRequest -MockWith {
            @([pscustomobject]@{ id = 'machine-1'; computerDnsName = 'PC-042'; onboardingStatus = 'Onboarded' })
        }
        Mock -CommandName New-GraphPOSTRequest -MockWith {
            $script:Posts.Add([pscustomobject]@{ Uri = $uri; Body = [string]$body })
        }
    }

    It 'isolates fully: selective would still let the compromised mailbox talk' {
        $Result = Set-PSITMdeIsolation -AzureADDeviceId 'aad-device-1' -TenantFilter 'contoso.test' -Analyst 'a'

        $script:Posts.Count | Should -Be 1
        $script:Posts[0].Uri | Should -BeLike '*/machines/machine-1/isolate'
        $script:Posts[0].Body | Should -BeLike '*"IsolationType":"Full"*'
        $Result.Action | Should -Be 'isolate'
        $Result.Results[0].state | Should -Be 'success'
    }

    It 'releases on request, and a release carries no isolation type' {
        $Result = Set-PSITMdeIsolation -AzureADDeviceId 'aad-device-1' -TenantFilter 'contoso.test' -Analyst 'a' -Release

        $script:Posts[0].Uri | Should -BeLike '*/machines/machine-1/unisolate'
        $script:Posts[0].Body | Should -Not -BeLike '*IsolationType*'
        $Result.Action | Should -Be 'unisolate'
    }

    It 'carries the analyst into the comment, which is what the portal shows later' {
        $null = Set-PSITMdeIsolation -AzureADDeviceId 'aad-device-1' -TenantFilter 'contoso.test' -Analyst 'analyste@example.test'
        $script:Posts[0].Body | Should -BeLike '*analyste@example.test*'
    }

    It 'refuses a device with no Entra id rather than isolating the wrong machine' {
        { Set-PSITMdeIsolation -AzureADDeviceId '00000000-0000-0000-0000-000000000000' -TenantFilter 'contoso.test' -Analyst 'a' } |
            Should -Throw '*no Entra device id*'
        $script:Posts.Count | Should -Be 0
    }

    It 'says the machine is not onboarded rather than reporting a silent success' {
        Mock -CommandName New-GraphGetRequest -MockWith {
            @([pscustomobject]@{ id = 'machine-1'; onboardingStatus = 'Can be onboarded' })
        }
        { Set-PSITMdeIsolation -AzureADDeviceId 'aad-device-1' -TenantFilter 'contoso.test' -Analyst 'a' } |
            Should -Throw '*none are currently onboarded*'
    }

    It 'reports a failing machine record without hiding the others' {
        Mock -CommandName New-GraphGetRequest -MockWith {
            @(
                [pscustomobject]@{ id = 'machine-1'; computerDnsName = 'PC-042'; onboardingStatus = 'Onboarded' }
                [pscustomobject]@{ id = 'machine-2'; computerDnsName = 'PC-042-old'; onboardingStatus = 'Onboarded' }
            )
        }
        Mock -CommandName New-GraphPOSTRequest -MockWith {
            if ($uri -like '*machine-2*') { throw 'Machine not found' }
        }

        $Result = Set-PSITMdeIsolation -AzureADDeviceId 'aad-device-1' -TenantFilter 'contoso.test' -Analyst 'a'

        @($Result.Results | Where-Object { $_.state -eq 'success' }).Count | Should -Be 1
        @($Result.Results | Where-Object { $_.state -eq 'error' }).Count | Should -Be 1
    }
}

Describe 'Invoke-PSITMailRemediation' {
    BeforeEach {
        $script:Posts = [System.Collections.Generic.List[object]]::new()
        Mock -CommandName Write-LogMessage -MockWith { }
        Mock -CommandName New-GraphGetRequest -MockWith {
            @(
                [pscustomobject]@{ networkMessageId = 'b0f2a3c4-1111-2222-3333-444455556666'; recipientEmailAddress = 'a.tkachenko@contoso.test' }
                [pscustomobject]@{ networkMessageId = 'b0f2a3c4-1111-2222-3333-444455556666'; recipientEmailAddress = 'other@contoso.test' }
            )
        }
        Mock -CommandName New-GraphPOSTRequest -MockWith {
            $script:Posts.Add([pscustomobject]@{ Uri = $uri; Body = [string]$body })
        }
    }

    It 'submits a soft delete, never a hard delete' {
        $Result = Invoke-PSITMailRemediation -TenantFilter 'contoso.test' -NetworkMessageId 'b0f2a3c4-1111-2222-3333-444455556666' -Analyst 'a'

        $script:Posts.Count | Should -Be 1
        $script:Posts[0].Uri | Should -BeLike '*analyzedEmails/remediate'
        $script:Posts[0].Body | Should -BeLike '*"remediationAction":"softDelete"*'
        $Result.Action | Should -Be 'softDelete'
    }

    It 'purges every recipient copy when none is named' {
        $Result = Invoke-PSITMailRemediation -TenantFilter 'contoso.test' -NetworkMessageId 'b0f2a3c4-1111-2222-3333-444455556666' -Analyst 'a'
        @($Result.Recipients).Count | Should -Be 2
    }

    It 'purges only the copies of the recipients named' {
        $Result = Invoke-PSITMailRemediation -TenantFilter 'contoso.test' -NetworkMessageId 'b0f2a3c4-1111-2222-3333-444455556666' -Recipients @('A.Tkachenko@contoso.test') -Analyst 'a'

        @($Result.Recipients).Count | Should -Be 1
        $Result.Recipients[0] | Should -Be 'a.tkachenko@contoso.test'
    }

    It 'refuses an identifier that is not a message id' {
        { Invoke-PSITMailRemediation -TenantFilter 'contoso.test' -NetworkMessageId 'not-a-guid' -Analyst 'a' } |
            Should -Throw '*is not a network message id*'
    }

    It 'says the message was not found rather than reporting an empty success' {
        Mock -CommandName New-GraphGetRequest -MockWith { @() }
        { Invoke-PSITMailRemediation -TenantFilter 'contoso.test' -NetworkMessageId 'b0f2a3c4-1111-2222-3333-444455556666' -Analyst 'a' } |
            Should -Throw '*No analyzed email found*'
        $script:Posts.Count | Should -Be 0
    }

    It 'refuses when none of the named recipients actually received the message' {
        { Invoke-PSITMailRemediation -TenantFilter 'contoso.test' -NetworkMessageId 'b0f2a3c4-1111-2222-3333-444455556666' -Recipients @('nobody@contoso.test') -Analyst 'a' } |
            Should -Throw '*None of the recipients*'
        $script:Posts.Count | Should -Be 0
    }
}
