# Pester tests for the two functions that keep service traffic and ordinary work out of the BEC
# signals: Test-PSITBecServiceIp (is this address Microsoft's own infrastructure?) and
# Get-PSITBecOutboundClassification (which outbound rows may the heuristics look at?).
#
# The fixtures come from the case that motivated them: 177 outbound rows of which 166 were
# automatic replies submitted from 2603:10a6:803:81::32, geolocated to Canada, counted as
# "activity outside the user's country" by the upstream report.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/PSIT/Test-PSITBecServiceIp.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/PSIT/Get-PSITBecOutboundClassification.ps1')

    function New-TraceRow {
        param($Subject, $Recipient, $FromIp, $Received, $TraceId)
        [pscustomobject]@{
            MessageTraceId   = $TraceId ?? [guid]::NewGuid().ToString()
            Subject          = $Subject
            RecipientAddress = $Recipient
            FromIP           = $FromIp
            Received         = $Received
            Status           = 'Delivered'
        }
    }
}

Describe 'Test-PSITBecServiceIp' {
    It 'recognises the Exchange Online IPv6 range that submits automatic replies' {
        Test-PSITBecServiceIp -Ip '2603:10a6:803:81::32' | Should -BeTrue
    }

    It 'recognises the documented EOP IPv4 ranges' {
        Test-PSITBecServiceIp -Ip '40.107.13.25' | Should -BeTrue
        Test-PSITBecServiceIp -Ip '104.47.55.138' | Should -BeTrue
        Test-PSITBecServiceIp -Ip '52.101.42.7' | Should -BeTrue
    }

    It 'does not claim a neighbouring range that is not Microsoft' {
        # 2603:2000:: shares the first 16 bits with 2603:1000::/24 but not the prefix.
        Test-PSITBecServiceIp -Ip '2603:2000::1' | Should -BeFalse
        Test-PSITBecServiceIp -Ip '40.94.0.1' | Should -BeFalse
    }

    It 'leaves a real user address alone' {
        Test-PSITBecServiceIp -Ip '198.51.100.7' | Should -BeFalse
        Test-PSITBecServiceIp -Ip '203.0.113.42' | Should -BeFalse
    }

    It 'uses the autonomous system name when the address is outside the prefix list' {
        Test-PSITBecServiceIp -Ip '13.107.6.152' -GeoInfo ([pscustomobject]@{ ASName = 'MICROSOFT-CORP-MSN-AS-BLOCK' }) | Should -BeTrue
        Test-PSITBecServiceIp -Ip '13.107.6.152' -GeoInfo ([pscustomobject]@{ ASName = 'TELECOM ITALIA' }) | Should -BeFalse
    }

    It 'tolerates ports, brackets and rubbish without throwing' {
        Test-PSITBecServiceIp -Ip '[2603:10a6:803:81::32]' | Should -BeTrue
        Test-PSITBecServiceIp -Ip '40.107.13.25:25' | Should -BeTrue
        Test-PSITBecServiceIp -Ip 'not-an-address' | Should -BeFalse
        Test-PSITBecServiceIp -Ip '' | Should -BeFalse
        Test-PSITBecServiceIp -Ip $null | Should -BeFalse
    }
}

Describe 'Get-PSITBecOutboundClassification' {
    BeforeEach {
        $script:Rows = @(
            # 4 automatic replies from the Exchange Online submission address.
            New-TraceRow 'Réponse automatique : absence REGION TOULOUSAINE' 'agnes@partner.test' '2603:10a6:803:81::32' '2026-08-20T10:13:07Z'
            New-TraceRow 'Réponse automatique : DA2041605 DEVIS' 'buyer@client.test' '2603:10a6:803:81::32' '2026-08-20T10:13:08Z'
            New-TraceRow 'Automatic reply: out of office' 'buyer2@client.test' '2603:10a6:803:81::32' '2026-08-20T10:13:09Z'
            New-TraceRow 'Undeliverable: réunion projet' 'nobody@client.test' '2603:10a6:803:81::32' '2026-08-20T10:13:10Z'
            # Internal mail from the user's own workstation.
            New-TraceRow 'Re: réunion projet aout 2026' 'a.servanty@geser.test' '198.51.100.7' '2026-08-20T10:07:48Z'
            New-TraceRow 'Re: réunion projet aout 2026' 's.baji@geser.test' '198.51.100.7' '2026-08-20T10:07:48Z'
            # Genuine external mail.
            New-TraceRow 'Fwd: consultation AO2606960' 'contact@sopra.test' '198.51.100.7' '2026-08-20T10:03:08Z'
        )
    }

    It 'separates service, internal and analysable traffic' {
        $Result = Get-PSITBecOutboundClassification -TraceRows $script:Rows -SenderAddress 'p.martin@geser.test'

        $Result.TotalRecipients | Should -Be 7
        $Result.SystemGeneratedMessages | Should -Be 4
        $Result.ServiceIpRecipients | Should -Be 4
        $Result.InternalRecipients | Should -Be 2
        $Result.ExternalRecipients | Should -Be 5
        # Only the one genuine external, human-sent message survives for the heuristics.
        $Result.AnalysableMessages | Should -Be 1
    }

    It 'tags the automatic replies rather than dropping them, so the exclusion stays auditable' {
        $Result = Get-PSITBecOutboundClassification -TraceRows $script:Rows -SenderAddress 'p.martin@geser.test'

        @($Result.Rows).Count | Should -Be 7
        @($Result.Rows | Where-Object { $_.SystemGenerated }).Count | Should -Be 4
        @($Result.Rows | Where-Object { $_.ServiceIp }).Count | Should -Be 4
    }

    It 'does not call a normal morning a mass-mail campaign' {
        $Result = Get-PSITBecOutboundClassification -TraceRows $script:Rows -SenderAddress 'p.martin@geser.test'
        $Result.Flagged | Should -BeFalse
        @($Result.Bursts).Count | Should -Be 0
    }

    It 'still flags a real burst of external mail' {
        $Burst = 1..12 | ForEach-Object {
            New-TraceRow "Facture $_" "victim$_@client.test" '203.0.113.7' '2026-08-19T07:11:00Z'
        }
        $Result = Get-PSITBecOutboundClassification -TraceRows $Burst -SenderAddress 'p.martin@geser.test'

        $Result.Flagged | Should -BeTrue
        @($Result.Bursts).Count | Should -Be 1
        $Result.Bursts[0].MessageCount | Should -Be 12
    }

    It 'flags a repeated subject sent to many external recipients' {
        $Campaign = 1..6 | ForEach-Object {
            New-TraceRow 'Mise a jour de vos coordonnees bancaires' "victim$_@client.test" '203.0.113.7' "2026-08-19T0$($_):00:00Z"
        }
        $Result = Get-PSITBecOutboundClassification -TraceRows $Campaign -SenderAddress 'p.martin@geser.test'

        $Result.FlaggedSubjectCount | Should -Be 1
        $Result.RepeatedSubjects[0].MessageCount | Should -Be 6
        $Result.RepeatedSubjects[0].FirstSent | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$'
    }

    It 'never flags a campaign built only out of automatic replies' {
        $AutoOnly = 1..12 | ForEach-Object {
            New-TraceRow 'Réponse automatique : absence' "someone$_@client.test" '2603:10a6:803:81::32' '2026-08-19T07:11:00Z'
        }
        $Result = Get-PSITBecOutboundClassification -TraceRows $AutoOnly -SenderAddress 'p.martin@geser.test'

        $Result.Flagged | Should -BeFalse
        $Result.SystemGeneratedMessages | Should -Be 12
        $Result.AnalysableMessages | Should -Be 0
    }

    It 'returns empty counters rather than throwing on no trace at all' {
        $Result = Get-PSITBecOutboundClassification -TraceRows @() -SenderAddress 'p.martin@geser.test'

        $Result.TotalRecipients | Should -Be 0
        $Result.Flagged | Should -BeFalse
    }
}
