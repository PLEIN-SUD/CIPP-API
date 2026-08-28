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

    It 'sends no tag at all when the caller sent none' {
        $Request = New-WebhookRequest -Body @{ Subject = '[SOC x Contoso] - Test - user' }
        $Result = Invoke-PublicPSITSocWebhook -Request $Request -TriggerMetadata $null

        $Result.Body.Ingested | Should -BeTrue
        Should -Invoke Set-PSITSocCase -Times 0 -ParameterFilter { $null -ne $SeverityTag -and $SeverityTag -ne '' }
    }
}
