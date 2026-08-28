# Pester tests for turning an external SOC subject line into an alert type.
#
# Three things are pinned. Pattern order, because the binary activity pattern matches almost any
# subject starting with "Activite" and would swallow the identity labels if it were tried first.
# The catch-all, because an emitter adds rules without telling anyone and an unrecognised subject
# must open a case rather than disappear. And the separation of type from detection product,
# because the SOC transports Defender, Defender for Office and Entra detections alike: filing an
# endpoint detection under the channel it arrived through is how the same event gets counted twice.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/PSIT/Resolve-PSITSocAlertType.ps1')

    $script:Catalogue = Get-Content -Path (Join-Path $RepoRoot 'Config/PSITSocAlertTypes.json') -Raw -Encoding utf8 | ConvertFrom-Json
    $script:Resolve = {
        param($Subject)
        Resolve-PSITSocAlertType -Subject $Subject -Catalogue $script:Catalogue
    }
}

Describe 'Resolve-PSITSocAlertType' {
    It 'reads the client scope, the label and the target out of a subject' {
        $Result = & $script:Resolve '[SOC x CLIENT_A] - Connexion et activité dans deux pays - utilisateur@client-a.test'

        $Result.Scope | Should -Be 'CLIENT_A'
        $Result.Target | Should -Be 'utilisateur@client-a.test'
        $Result.TypeId | Should -Be 2
    }

    It 'strips stacked reply prefixes before matching' {
        # A forwarded forward carries several, and the label sits behind all of them.
        $Result = & $script:Resolve 'RE: TR: [EXT] [SOC x CLIENT_A] - Connexion et activité dans deux pays'
        $Result.TypeId | Should -Be 2
        $Result.Matched | Should -BeTrue
    }

    It 'tries the specific identity labels before the generic activity pattern' {
        # The order in the configuration is load bearing: reversed, this subject would resolve to
        # the binary activity type because it starts with a word the generic pattern accepts.
        $Result = & $script:Resolve '[SOC x CLIENT_A] - Ajout de droit privilégié par l''utilisateur admin@client-a.test'
        $Result.LabelId | Should -Be 'IDENT_PRIV_ROLE_ADD'
        $Result.TypeId | Should -Be 4
    }

    It 'recovers the target from the label when no separator carries it' {
        $Result = & $script:Resolve '[SOC x CLIENT_A] - Ajout de droit privilégié par l''utilisateur admin@client-a.test'
        $Result.Target | Should -Be 'admin@client-a.test'
    }

    It 'reports the detection product, not the channel the alert arrived through' {
        # The SOC transports Defender detections. Filing them under the SOC would attribute a
        # false source and double count the same event when it also arrives from the portal.
        (& $script:Resolve '[SOC x CLIENT_A] - Comportement de commande et contrôle bloqué - Poste PC-001').DetectionSource | Should -Be 'xdr'
        (& $script:Resolve '[SOC x CLIENT_A] - Connexion et activité dans deux pays').DetectionSource | Should -Be 'entra'
        (& $script:Resolve '[SOC x CLIENT_A] - Alerte mail de phishing non bloqués').DetectionSource | Should -Be 'mdo'
    }

    It 'reads a portal notification subject, which carries no scope prefix at all' {
        $Result = & $script:Resolve "An active 'Wacatac' malware was blocked"
        $Result.TypeId | Should -Be 13
        $Result.LabelId | Should -Be 'LH_MALWARE_ACTIVE_BLOCKED'
    }

    It 'sends both malware wordings to the same type' {
        (& $script:Resolve "'Malgent' malware was prevented").TypeId | Should -Be 13
        (& $script:Resolve "An active 'Wacatac' malware was blocked").TypeId | Should -Be 13
    }

    It 'opens a case on the catch-all type rather than dropping an unknown subject' {
        # The emitter adds rules without telling anyone. An unrecognised subject is a taxonomy to
        # extend, and dropping it would make that invisible.
        $Result = & $script:Resolve '[SOC x CLIENT_A] - Une règle inédite apparue ce matin'
        $Result.TypeId | Should -Be 99
        $Result.LabelId | Should -Be 'CATCHALL'
        $Result.Matched | Should -BeFalse
        # The scope still comes through, so the case reaches the right client.
        $Result.Scope | Should -Be 'CLIENT_A'
    }

    It 'answers on an empty subject instead of throwing' {
        (& $script:Resolve '').TypeId | Should -Be 99
        (& $script:Resolve $null).Matched | Should -BeFalse
    }

    It 'recognises an alert this portal cannot investigate as out of scope, not as unknown' {
        # Google Workspace and third-party endpoint alerts are deliberately not covered. Marking
        # them out of scope keeps them out of the list of taxonomy gaps to fix.
        $Result = & $script:Resolve '[SOC x CLIENT_A] - Téléchargement massif de fichiers Google Workspace'
        $Result.OutOfScope | Should -BeTrue
        $Result.Status | Should -Be 'OUT_OF_SCOPE'
        $Result.LabelId | Should -Be 'DATA_MASS_DOWNLOAD'
    }

    It 'marks the correlation rule as watched, since no message carrying it has been seen' {
        $Result = & $script:Resolve '[SOC x CLIENT_A] - Connexion impossible - utilisateur@client-a.test'
        $Result.TypeId | Should -Be 3
        $Result.Status | Should -Be 'WATCH'
    }
}

Describe 'the emitter ticket number' {
    # The emitter's new subject format pastes its own ticket number in front of the block.
    # Replying to the emitter goes through that number, so the case keeps it.
    It 'captures the number pasted in front of the block' {
        $Result = & $script:Resolve '#123698 - [SOC x CLIENT_A] - Connexion et activité dans deux pays - u@client-a.test'
        $Result.EmitterTicket | Should -Be '123698'
        $Result.TypeId | Should -Be 2
    }

    It 'stays empty on a subject without one, never invented' {
        (& $script:Resolve '[SOC x CLIENT_A] - Connexion et activité dans deux pays').EmitterTicket | Should -BeNullOrEmpty
    }
}

Describe 'the active-process wording' {
    # The emitter's new EDR rule, met on a real alert: it lands on the suspicious-binary type
    # directly now, instead of parking on the catch-all for an analyst to reclassify.
    It 'maps to the suspicious-binary type, junk prefix and all' {
        $Result = & $script:Resolve '#123698 - [SOC x CLIENT_A] - Processus opensupdater actif détecté - poste-01.client-a.local'
        $Result.TypeId | Should -Be 11
        $Result.LabelId | Should -Be 'EDR_PROCESS_ACTIVE'
        $Result.Target | Should -Be 'poste-01.client-a.local'
        $Result.EmitterTicket | Should -Be '123698'
    }

    It 'does not swallow the identity labels: the generic order still holds' {
        (& $script:Resolve '[SOC x CLIENT_A] - Ajout de droit privilégié par l''utilisateur a@client-a.test').TypeId | Should -Be 4
    }
}
