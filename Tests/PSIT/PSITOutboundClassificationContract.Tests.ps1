# The API side of a contract satisfied by two implementations of the same three rules:
# Get-PSITBecOutboundClassification here, which runs at collection time, and classifySentMessages
# in the CIPP front, which derives them for collections made before this function existed.
#
# Two implementations of one rule drift. The vector file is the contract; each repository runs it
# against its own implementation. The file is duplicated at:
#   CIPP-API/Tests/PSIT/psit-outbound-classification-vectors.json
#   CIPP/tests/fixtures/psit-outbound-classification-vectors.json
# Nothing enforces that across repositories: change one, change the other.

BeforeDiscovery {
    $ContractPath = Join-Path $PSScriptRoot 'psit-outbound-classification-vectors.json'
    $script:Contract = Get-Content -Path $ContractPath -Raw -Encoding utf8 | ConvertFrom-Json
    # Hashtables, not the raw objects: Pester only expands <name> in a test title from hashtable
    # keys, and a contract test whose failures all read "classifies  as the contract requires" is
    # useless at the moment it matters.
    $script:Cases = @($script:Contract.cases | ForEach-Object {
            @{ name = $_.name; expected = $_.expected }
        })
}

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/PSIT/Test-PSITBecServiceIp.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/PSIT/Get-PSITBecOutboundClassification.ps1')

    $ContractPath = Join-Path $PSScriptRoot 'psit-outbound-classification-vectors.json'
    $Contract = Get-Content -Path $ContractPath -Raw -Encoding utf8 | ConvertFrom-Json

    # One row per case, classified in a single pass, so the counters are exercised too.
    $Index = 0
    $Rows = foreach ($Case in $Contract.cases) {
        [pscustomobject]@{
            MessageTraceId   = "m$Index"
            Subject          = $Case.subject
            RecipientAddress = $Case.recipientAddress
            FromIP           = $Case.fromIp
            Received         = '2026-08-20T07:00:00Z'
        }
        $Index++
    }

    $script:Result = Get-PSITBecOutboundClassification -TraceRows @($Rows) -SenderAddress $Contract.senderAddress
    $script:ByIndex = @($script:Result.Rows)
    $script:Contract = $Contract
}

Describe 'Outbound classification contract' {
    It 'classifies <name> as the contract requires' -ForEach $script:Cases {
        $Index = [array]::IndexOf(@($script:Contract.cases.name), $name)
        $Row = $script:ByIndex[$Index]

        [bool]$Row.SystemGenerated | Should -Be ([bool]$expected.systemGenerated) -Because "SystemGenerated for '$name'"
        [bool]$Row.ServiceIp | Should -Be ([bool]$expected.serviceIp) -Because "ServiceIp for '$name'"
        [bool]$Row.Internal | Should -Be ([bool]$expected.internal) -Because "Internal for '$name'"
    }

    It 'derives the analysable subset from the same rules' {
        $ExpectedAnalysable = @($script:Contract.cases | Where-Object {
                -not $_.expected.systemGenerated -and -not $_.expected.internal
            }).Count

        @($script:Result.AnalysableRows).Count | Should -Be $ExpectedAnalysable
        $script:Result.TotalRecipients | Should -Be @($script:Contract.cases).Count
        $script:Result.InternalRecipients | Should -Be @($script:Contract.cases | Where-Object { $_.expected.internal }).Count
        $script:Result.ServiceIpRecipients | Should -Be @($script:Contract.cases | Where-Object { $_.expected.serviceIp }).Count
    }

    It 'keeps the full picture alongside the analysable subset' {
        # The counters must never hide what was excluded: a reader sees 17 recipients collected, of
        # which 8 service-generated, rather than either number on its own.
        $script:Result.TotalRecipients | Should -BeGreaterThan @($script:Result.AnalysableRows).Count
        $script:Result.SystemGeneratedMessages | Should -BeGreaterThan 0
    }
}
