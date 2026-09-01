# Pester tests for Invoke-PublicPSITSocWebhook.
#
# Covers the severity-tag contract: the emitter's words travel to the case verbatim, except
# 'Unknown', which is the automation's fallback for "the mail named no priority" - an absence,
# not a tag. Stored, it would shadow forever a Severity set by hand, because the queue displays
# the tag over the P level whenever one exists.

BeforeAll {
    # Resolve by name under Modules/ so the test survives the function moving between modules.
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $FunctionPath = Get-ChildItem -Path (Join-Path $RepoRoot 'Modules') -Recurse -Filter 'Invoke-PublicPSITSocWebhook.ps1' -File -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
    if (-not $FunctionPath) { throw 'Could not locate Invoke-PublicPSITSocWebhook.ps1 under Modules/' }

    # Azure Functions binding types do not exist outside the Functions host - fake them.
    class HttpResponseContext {
        [int]$StatusCode
        [object]$Body
    }

    # The endpoint references the unqualified [HttpStatusCode], which only resolves in the
    # Functions host. Register it as a type accelerator so the source parses here too.
    $Accelerators = [PSObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')
    if (-not ('HttpStatusCode' -as [type])) {
        $Accelerators::Add('HttpStatusCode', [System.Net.HttpStatusCode])
    }

    # Stub every CIPP helper the function calls so Pester's Mock has a command to replace.
    function Get-PSITSocWebhookSecret { }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $LogData) }
    function Resolve-PSITSocAlertType { param($Subject) }
    function Get-Tenants { param([switch]$IncludeErrors) }
    function Resolve-PSITSocTenant { param($Name, $Tenants) }
    function Set-PSITSocCase {
        param(
            $TenantFilter, $CaseId, $Analyst, $Source, $Title, $TypeId, $DetectionSource,
            $Severity, $SeverityTag, $ExternalRef, $TicketRef, $TicketUrl, $Entities, $LogAction
        )
    }
    function Get-CippException { param($Exception) }
    function Add-CippQueueMessage { param($Cmdlet, $Parameters, $Priority) }

    . $FunctionPath

    # One authenticated, resolvable, in-scope request; tests vary only the severity fields.
    function New-WebhookRequest {
        param([hashtable]$Body)
        @{
            Query   = @{ secret = 'the-secret' }
            Headers = @{ }
            Body    = ([PSCustomObject]$Body)
        }
    }
}

Describe 'Invoke-PublicPSITSocWebhook severity fields' {
    BeforeEach {
        Mock -CommandName Get-PSITSocWebhookSecret -MockWith { [PSCustomObject]@{ Secret = 'the-secret' } }
        Mock -CommandName Write-LogMessage -MockWith { }
        Mock -CommandName Resolve-PSITSocAlertType -MockWith {
            [PSCustomObject]@{
                TypeId = 3; LabelId = 'TEST_LABEL'; Label = 'Test label'; Scope = 'Contoso'
                Target = 'user@contoso.test'; DetectionSource = 'unknown'; Status = 'ACTIVE'
                EmitterTicket = ''; Matched = $true; OutOfScope = $false; Reason = ''
            }
        }
        Mock -CommandName Get-Tenants -MockWith { @() }
        Mock -CommandName Resolve-PSITSocTenant -MockWith {
            [PSCustomObject]@{ Tenant = 'contoso.test'; Method = 'displayName'; Reason = 'matched' }
        }
        Mock -CommandName Set-PSITSocCase -MockWith {
            [PSCustomObject]@{ CaseId = 'PSIT-SOC-1'; Tenant = 'contoso.test'; TypeId = 3 }
        }
    }

    It "forwards the emitter's tag to the case verbatim" {
        $Request = New-WebhookRequest -Body @{ Subject = '[SOC x Contoso] - Test - user'; SeverityTag = 'High Priority' }
        $Result = Invoke-PublicPSITSocWebhook -Request $Request -TriggerMetadata $null

        $Result.Body.Ingested | Should -BeTrue
        Should -Invoke Set-PSITSocCase -Times 1 -ParameterFilter { $SeverityTag -eq 'High Priority' }
    }

    It "drops the tag 'Unknown' instead of storing an absence as a value" {
        $Request = New-WebhookRequest -Body @{ Subject = '[SOC x Contoso] - Test - user'; SeverityTag = 'Unknown'; Severity = 'P2' }
        $Result = Invoke-PublicPSITSocWebhook -Request $Request -TriggerMetadata $null

        $Result.Body.Ingested | Should -BeTrue
        # The case write happens without the tag, and the P level still travels.
        Should -Invoke Set-PSITSocCase -Times 0 -ParameterFilter { $null -ne $SeverityTag -and $SeverityTag -ne '' }
        Should -Invoke Set-PSITSocCase -Times 1 -ParameterFilter { $Severity -eq 'P2' }
    }

    It 'keeps an emitter word out of the P level and files it as the tag instead' {
        # A replay that put the wording in Severity either lost the ingestion to the P1-P4
        # validation or filed a case that no longer sorts. Both were seen in production rows.
        $Request = New-WebhookRequest -Body @{ Subject = '[SOC x Contoso] - Test - user'; Severity = 'High Priority' }
        $Result = Invoke-PublicPSITSocWebhook -Request $Request -TriggerMetadata $null

        $Result.Body.Ingested | Should -BeTrue
        Should -Invoke Set-PSITSocCase -Times 0 -ParameterFilter { $null -ne $Severity -and $Severity -ne '' }
        Should -Invoke Set-PSITSocCase -Times 1 -ParameterFilter { $SeverityTag -eq 'High Priority' }
    }

    It 'never lets a stray word overwrite a tag the caller supplied' {
        $Request = New-WebhookRequest -Body @{ Subject = '[SOC x Contoso] - Test - user'; Severity = 'High Priority'; SeverityTag = 'Critical' }
        $null = Invoke-PublicPSITSocWebhook -Request $Request -TriggerMetadata $null
        Should -Invoke Set-PSITSocCase -Times 1 -ParameterFilter { $SeverityTag -eq 'Critical' }
    }

    It 'passes a real P level through untouched' {
        $Request = New-WebhookRequest -Body @{ Subject = '[SOC x Contoso] - Test - user'; Severity = 'P1' }
        $null = Invoke-PublicPSITSocWebhook -Request $Request -TriggerMetadata $null
        Should -Invoke Set-PSITSocCase -Times 1 -ParameterFilter { $Severity -eq 'P1' }
    }

    It 'sends no tag at all when the caller sent none' {
        $Request = New-WebhookRequest -Body @{ Subject = '[SOC x Contoso] - Test - user' }
        $Result = Invoke-PublicPSITSocWebhook -Request $Request -TriggerMetadata $null

        $Result.Body.Ingested | Should -BeTrue
        Should -Invoke Set-PSITSocCase -Times 0 -ParameterFilter { $null -ne $SeverityTag -and $SeverityTag -ne '' }
    }
}

Describe 'Invoke-PublicPSITSocWebhook enrichment queue' {
    BeforeEach {
        Mock -CommandName Get-PSITSocWebhookSecret -MockWith { [PSCustomObject]@{ Secret = 'the-secret' } }
        Mock -CommandName Write-LogMessage -MockWith { }
        Mock -CommandName Resolve-PSITSocAlertType -MockWith {
            [PSCustomObject]@{ InScope = $true; TypeId = 2; LabelId = 'IMPOSSIBLE_TRAVEL'; Status = 'matched'; Target = 'p.martin@client.test'; EmitterTicket = $null }
        }
        Mock -CommandName Get-Tenants -MockWith { @() }
        Mock -CommandName Resolve-PSITSocTenant -MockWith {
            [PSCustomObject]@{ Tenant = 'client.test'; Method = 'exact' }
        }
        Mock -CommandName Set-PSITSocCase -MockWith {
            [PSCustomObject]@{ CaseId = 'PSIT-SOC-1'; Tenant = 'client.test'; TypeId = 2 }
        }
        Mock -CommandName Add-CippQueueMessage -MockWith { $true }
    }

    It 'queues one enrichment for the dossier it just created' {
        $Response = Invoke-PublicPSITSocWebhook -Request (New-WebhookRequest -Body @{ Subject = 'Impossible travel'; TenantName = 'client' }) -TriggerMetadata $null

        $Response.StatusCode | Should -Be ([HttpStatusCode]::OK)
        Should -Invoke Add-CippQueueMessage -Times 1 -ParameterFilter {
            $Cmdlet -eq 'Start-PSITCaseEnrichment' -and $Parameters.CaseId -eq 'PSIT-SOC-1' -and $Parameters.TenantFilter -eq 'client.test'
        }
    }

    It 'says a deduplicated signal was attached, not ingested as a new dossier' {
        # The same incident arriving through a second transport: Set-PSITSocCase answers with the
        # existing dossier and the ephemeral Reattached marker, and the emitter's automation must
        # be able to tell the two outcomes apart.
        Mock -CommandName Set-PSITSocCase -MockWith {
            [PSCustomObject]@{ CaseId = 'PSIT-SOC-1'; Tenant = 'client.test'; TypeId = 2; Reattached = $true }
        }

        $Response = Invoke-PublicPSITSocWebhook -Request (New-WebhookRequest -Body @{ Subject = 'Impossible travel'; TenantName = 'client' }) -TriggerMetadata $null

        $Response.StatusCode | Should -Be ([HttpStatusCode]::OK)
        $Response.Body.Reattached | Should -BeTrue
        $Response.Body.Results | Should -Match 'attached to existing'
        $Response.Body.CaseId | Should -Be 'PSIT-SOC-1'
    }

    It 'a queue refusal never fails the ingestion: the dossier exists, the pre-fill is a bonus' {
        Mock -CommandName Add-CippQueueMessage -MockWith { throw 'queue down' }

        $Response = Invoke-PublicPSITSocWebhook -Request (New-WebhookRequest -Body @{ Subject = 'Impossible travel'; TenantName = 'client' }) -TriggerMetadata $null

        $Response.StatusCode | Should -Be ([HttpStatusCode]::OK)
        $Response.Body.Ingested | Should -BeTrue
        Should -Invoke Write-LogMessage -Times 1 -ParameterFilter { $message -match 'could not be queued' }
    }
}
