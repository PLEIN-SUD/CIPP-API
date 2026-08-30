# Pester tests for the chain of custody: an action that changes a tenant keeps a picture of what
# it changed.
#
# The rule was stated after a report described an application with no consent and no permission -
# the state the revocation had created, not the one that had been investigated. It applies to
# every remediation: the purge deletes the message that proves the phishing was delivered, and the
# isolation changes the machine record a report would quote.
#
# What is pinned here is that each helper returns its own before-picture, read before it acts.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:MailPath = Get-ChildItem -Path (Join-Path $RepoRoot 'Modules') -Recurse -Filter 'Invoke-PSITMailRemediation.ps1' -File |
        Select-Object -First 1 -ExpandProperty FullName
    $script:IsolationPath = Get-ChildItem -Path (Join-Path $RepoRoot 'Modules') -Recurse -Filter 'Set-PSITMdeIsolation.ps1' -File |
        Select-Object -First 1 -ExpandProperty FullName
    if (-not $script:MailPath -or -not $script:IsolationPath) { throw 'Could not locate the remediation helpers under Modules/' }

    function Get-PSITMailEvidence { param($TenantFilter, $NetworkMessageId, $ReceivedUtc) }
    function New-GraphGetRequest { param($uri, $tenantid, $scope, $AsApp, $NoAuthCheck) }
    function New-GraphPOSTRequest { param($uri, $tenantid, $body, $scope, $type, $AsApp) }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $LogData, $headers) }

    . $script:MailPath
    . $script:IsolationPath
}

Describe 'Invoke-PSITMailRemediation keeps what the purge removes' {
    BeforeEach {
        Mock -CommandName Write-LogMessage -MockWith { }
        Mock -CommandName New-GraphPOSTRequest -MockWith { @{} }
        Mock -CommandName Get-PSITMailEvidence -MockWith {
            [PSCustomObject]@{
                Message    = [PSCustomObject]@{
                    NetworkMessageId = '11111111-2222-3333-4444-555555555555'
                    Subject     = 'Votre facture est en attente'
                    Sender      = 'attaquant@ailleurs.test'
                    ReceivedUtc = '2026-08-28T07:00:00Z'
                }
                Recipients = @(
                    [PSCustomObject]@{ Recipient = 'compta@client.test'; DeliveryAction = 'Delivered'; StillDelivered = $true }
                    [PSCustomObject]@{ Recipient = 'direction@client.test'; DeliveryAction = 'Quarantined'; StillDelivered = $false }
                )
                Metadata   = [PSCustomObject]@{ RecipientCount = 2; StillDelivered = 1; Found = $true }
            }
        }
    }

    It 'returns the recipients and their delivery state as they were before the purge' {
        $Result = Invoke-PSITMailRemediation -TenantFilter 'client.test' -NetworkMessageId ([guid]::NewGuid().Guid) -Recipients @('compta@client.test') -ReceivedUtc '2026-08-28T07:00:00Z' -Analyst 'analyste@partner.test'

        $Result.EvidenceBefore | Should -Not -BeNullOrEmpty
        $Result.EvidenceBefore.subject | Should -Be 'Votre facture est en attente'
        $Result.EvidenceBefore.sender | Should -Be 'attaquant@ailleurs.test'
        $Result.EvidenceBefore.recipientCount | Should -Be 2
        # The number that justifies the purge, and the one the same read stops returning once the
        # message is gone.
        $Result.EvidenceBefore.stillDelivered | Should -Be 1
    }

    It 'names each recipient with what happened to their copy' {
        $Result = Invoke-PSITMailRemediation -TenantFilter 'client.test' -NetworkMessageId ([guid]::NewGuid().Guid) -Recipients @('compta@client.test') -ReceivedUtc '2026-08-28T07:00:00Z' -Analyst 'analyste@partner.test'

        $Delivered = $Result.EvidenceBefore.recipients | Where-Object { $_.recipient -eq 'compta@client.test' }
        $Delivered.stillDelivered | Should -BeTrue
        $Delivered.deliveryAction | Should -Be 'Delivered'
    }

    It 'stamps when the purge was asked for' {
        $Result = Invoke-PSITMailRemediation -TenantFilter 'client.test' -NetworkMessageId ([guid]::NewGuid().Guid) -Recipients @('compta@client.test') -ReceivedUtc '2026-08-28T07:00:00Z' -Analyst 'analyste@partner.test'
        $Result.EvidenceBefore.purgedUtc | Should -Not -BeNullOrEmpty
    }
}

Describe 'Set-PSITMdeIsolation keeps the machine as it was' {
    BeforeEach {
        Mock -CommandName Write-LogMessage -MockWith { }
        Mock -CommandName New-GraphPOSTRequest -MockWith { @{} }
        Mock -CommandName New-GraphGetRequest -MockWith {
            @([PSCustomObject]@{
                    id               = 'machine-1'
                    computerDnsName  = 'poste-compta.client.test'
                    onboardingStatus = 'Onboarded'
                    healthStatus     = 'Active'
                    riskScore        = 'High'
                    exposureLevel    = 'Medium'
                    isolationState   = 'NotIsolated'
                    lastSeen         = '2026-08-28T06:55:00Z'
                    osPlatform       = 'Windows11'
                })
        }
    }

    It 'returns the machine record read before the isolation was requested' {
        $Result = Set-PSITMdeIsolation -TenantFilter 'client.test' -AzureADDeviceId 'device-guid' -Analyst 'analyste@partner.test' -Comment 'Dossier PSIT-SOC-1'

        $Result.MachinesBefore | Should -HaveCount 1
        # The risk that justified the cut, and the state the cut is about to replace.
        $Result.MachinesBefore[0].riskScore | Should -Be 'High'
        $Result.MachinesBefore[0].isolationState | Should -Be 'NotIsolated'
        $Result.MachinesBefore[0].computerDnsName | Should -Be 'poste-compta.client.test'
    }

    It 'stamps when the action was taken' {
        $Result = Set-PSITMdeIsolation -TenantFilter 'client.test' -AzureADDeviceId 'device-guid' -Analyst 'analyste@partner.test' -Comment 'Dossier PSIT-SOC-1'
        $Result.ActionedUtc | Should -Not -BeNullOrEmpty
    }
}
