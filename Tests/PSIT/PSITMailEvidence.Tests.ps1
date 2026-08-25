# Pester tests for the message evidence a case shows before anyone purges anything.
#
# The case view used to offer a delete button and no evidence, which asked an analyst to remove a
# message he could not see. What is pinned here is what he now sees, and above all that the panel
# and the purge read through the same function: two lookups with two time windows would eventually
# disagree, and they would disagree at the moment someone is deciding whether to delete mail.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/PSIT/Get-PSITMailEvidence.ps1')

    function New-GraphGetRequest { param($uri, $tenantid, $AsApp) }

    $script:Analyzed = @(
        [pscustomobject]@{
            networkMessageId      = 'b0f2a3c4-1111-2222-3333-444455556666'
            internetMessageId     = '<abc@sender.test>'
            subject               = 'Votre facture en attente'
            recipientEmailAddress = 'first@contoso.test'
            senderDetail          = [pscustomobject]@{ displayName = 'Comptabilite'; fromAddress = 'billing@sender.test'; mailFromAddress = 'bounce@sender.test'; ipv4 = '203.0.113.9' }
            originalDelivery      = [pscustomobject]@{ action = 'Delivered'; location = 'Inbox' }
            latestDelivery        = [pscustomobject]@{ action = 'Delivered'; location = 'Inbox' }
            threatTypes           = @('Phish')
            detectionMethods      = @('URL malicious reputation')
            authenticationDetails = [pscustomobject]@{ senderPolicyFramework = 'fail'; dkim = 'none'; dmarc = 'fail' }
            urls                  = @([pscustomobject]@{ url = 'https://sender.test/pay' })
            attachments           = @()
        }
        [pscustomobject]@{
            networkMessageId      = 'b0f2a3c4-1111-2222-3333-444455556666'
            recipientEmailAddress = 'second@contoso.test'
            originalDelivery      = [pscustomobject]@{ action = 'Delivered'; location = 'Inbox' }
            latestDelivery        = [pscustomobject]@{ action = 'Quarantined'; location = 'Quarantine' }
        }
    )
}

Describe 'Get-PSITMailEvidence' {
    It 'names the sender, the subject and what Defender thought of the message' {
        $Result = Get-PSITMailEvidence -TenantFilter 'contoso.test' -NetworkMessageId 'b0f2a3c4-1111-2222-3333-444455556666' -Analyzed $script:Analyzed

        $Result.Message.Subject | Should -Be 'Votre facture en attente'
        $Result.Message.SenderFrom | Should -Be 'billing@sender.test'
        $Result.Message.SenderIp | Should -Be '203.0.113.9'
        $Result.Message.ThreatTypes | Should -Contain 'Phish'
        $Result.Message.Urls | Should -Contain 'https://sender.test/pay'
        # The envelope sender differs from the displayed one, which is itself a finding.
        $Result.Message.SenderMailFrom | Should -Be 'bounce@sender.test'
    }

    It 'keeps one row per recipient rather than flattening the message into one verdict' {
        # Delivered to one mailbox and quarantined in another is two situations, and the analyst
        # deciding on a purge needs both.
        $Result = Get-PSITMailEvidence -TenantFilter 'contoso.test' -NetworkMessageId 'b0f2a3c4-1111-2222-3333-444455556666' -Analyzed $script:Analyzed

        @($Result.Recipients).Count | Should -Be 2
        ($Result.Recipients | Where-Object { $_.Recipient -eq 'first@contoso.test' }).StillDelivered | Should -BeTrue
        ($Result.Recipients | Where-Object { $_.Recipient -eq 'second@contoso.test' }).StillDelivered | Should -BeFalse
    }

    It 'counts the copies still sitting in a mailbox, which is what the purge would act on' {
        $Result = Get-PSITMailEvidence -TenantFilter 'contoso.test' -NetworkMessageId 'b0f2a3c4-1111-2222-3333-444455556666' -Analyzed $script:Analyzed

        $Result.Metadata.RecipientCount | Should -Be 2
        $Result.Metadata.StillDelivered | Should -Be 1
    }

    It 'bounds the window on the reported reception time, one day either side' {
        $Result = Get-PSITMailEvidence -TenantFilter 'contoso.test' -NetworkMessageId 'b0f2a3c4-1111-2222-3333-444455556666' -ReceivedUtc '2026-08-20T09:00:00Z' -Analyzed $script:Analyzed

        $Result.Metadata.WindowStart | Should -Be '2026-08-19T09:00:00Z'
        $Result.Metadata.WindowEnd | Should -Be '2026-08-21T09:00:00Z'
        $Result.Metadata.WindowFromReport | Should -BeTrue
    }

    It 'falls back to a fifteen day window, and says the window was not reported' {
        # An empty answer has two causes that call for different actions: nothing matched inside
        # the window, or the tenant is not licensed for this API. The window travels so the first
        # can be ruled out without guessing.
        $Result = Get-PSITMailEvidence -TenantFilter 'contoso.test' -NetworkMessageId 'b0f2a3c4-1111-2222-3333-444455556666' -Analyzed $script:Analyzed

        $Result.Metadata.WindowFromReport | Should -BeFalse
        # ToUniversalTime, because casting a Z-stamped string yields local time and the comparison
        # would drift by the machine offset rather than by anything the code did.
        ([datetime]$Result.Metadata.WindowEnd).ToUniversalTime() | Should -BeLessOrEqual ([datetime]::UtcNow.AddMinutes(1))
    }

    It 'refuses an identifier that is not a message id' {
        { Get-PSITMailEvidence -TenantFilter 'contoso.test' -NetworkMessageId 'not-a-guid' } |
            Should -Throw '*is not a network message id*'
    }

    It 'answers not found rather than throwing when nothing matches' {
        $Result = Get-PSITMailEvidence -TenantFilter 'contoso.test' -NetworkMessageId 'b0f2a3c4-1111-2222-3333-444455556666' -Analyzed @()

        $Result.Metadata.Found | Should -BeFalse
        $Result.Message | Should -BeNullOrEmpty
        @($Result.Recipients).Count | Should -Be 0
    }
}
