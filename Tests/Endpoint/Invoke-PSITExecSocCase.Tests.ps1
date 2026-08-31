# Pester tests for Invoke-PSITExecSocCase.
#
# Covers the tenant guard. A dossier is stored under its tenant, so an unknown one files it where
# nobody looks for it, and every later read from the case view targets a tenant that does not
# exist. An adversarial review found a caller sending the literal string 'tenant' - an unresolved
# column name falls back to itself - and the endpoint answered 200 with a case id under a client
# of that name. Names that resolve to nothing are refused here rather than written.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $FunctionPath = Get-ChildItem -Path (Join-Path $RepoRoot 'Modules') -Recurse -Filter 'Invoke-PSITExecSocCase.ps1' -File -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
    if (-not $FunctionPath) { throw 'Could not locate Invoke-PSITExecSocCase.ps1 under Modules/' }

    # Azure Functions binding types do not exist outside the Functions host - fake them.
    class HttpResponseContext {
        [int]$StatusCode
        [object]$Body
    }
    $Accelerators = [PSObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')
    if (-not ('HttpStatusCode' -as [type])) {
        $Accelerators::Add('HttpStatusCode', [System.Net.HttpStatusCode])
    }

    function Get-PSITSocRequestValue { param($Value) return $Value }
    function Get-PSITBecAnalyst { param($Headers) return 'analyste@partner.test' }
    function Get-Tenants { param($TenantFilter, [switch]$IncludeErrors) }
    function Get-PSITSocCase { param($TenantFilter, $CaseId, $Status, $Source, $ExternalRef) }
    function Write-LogMessage { param($headers, $API, $tenant, $message, $sev, $LogData) }
    function Get-CippException { param($Exception) }
    function Set-PSITSocCase {
        param(
            $TenantFilter, $CaseId, $Analyst, $Source, $Title, $TypeId, $Severity, $SeverityTag,
            $Status, $ExternalRef, $TicketRef, $TicketUrl, $Verdict, $Justification, $AssignedTo,
            $Entities, $GuideProgress, $LogAction, $DetectionSource
        )
    }

    . $FunctionPath

    function New-CaseRequest {
        param([hashtable]$Body)
        @{ Headers = @{ }; Body = ([PSCustomObject]$Body) }
    }
}

Describe 'Invoke-PSITExecSocCase tenant guard' {
    BeforeEach {
        Mock -CommandName Write-LogMessage -MockWith { }
        Mock -CommandName Set-PSITSocCase -MockWith {
            [PSCustomObject]@{ CaseId = 'PSIT-SOC-1'; Tenant = 'contoso.test' }
        }
        Mock -CommandName Get-Tenants -MockWith {
            param($TenantFilter)
            if ($TenantFilter -eq 'contoso.test') { @([PSCustomObject]@{ defaultDomainName = 'contoso.test' }) } else { @() }
        }
    }

    It 'refuses a tenant no managed client answers to, and writes nothing' {
        $Result = Invoke-PSITExecSocCase -Request (New-CaseRequest -Body @{ tenantFilter = 'tenant'; Title = 'Test' }) -TriggerMetadata $null

        $Result.StatusCode | Should -Be ([HttpStatusCode]::BadRequest)
        $Result.Body.Results | Should -Match "No managed tenant matches 'tenant'"
        Should -Invoke Set-PSITSocCase -Times 0
    }

    It 'logs the refusal, so a caller sending the wrong field is visible' {
        $null = Invoke-PSITExecSocCase -Request (New-CaseRequest -Body @{ tenantFilter = 'tenant'; Title = 'Test' }) -TriggerMetadata $null
        Should -Invoke Write-LogMessage -Times 1 -ParameterFilter { $sev -eq 'Warn' -and $message -match 'unknown tenant' }
    }

    It 'lets a managed tenant through' {
        $Result = Invoke-PSITExecSocCase -Request (New-CaseRequest -Body @{ tenantFilter = 'contoso.test'; Title = 'Test' }) -TriggerMetadata $null

        $Result.StatusCode | Should -Be ([HttpStatusCode]::OK)
        Should -Invoke Set-PSITSocCase -Times 1
    }

    It 'still requires a tenant at all' {
        $Result = Invoke-PSITExecSocCase -Request (New-CaseRequest -Body @{ Title = 'Test' }) -TriggerMetadata $null
        $Result.StatusCode | Should -Be ([HttpStatusCode]::BadRequest)
        $Result.Body.Results | Should -Match 'tenantFilter is required'
    }
}

Describe 'Invoke-PSITExecSocCase take-ownership lock' {
    BeforeEach {
        Mock -CommandName Write-LogMessage -MockWith { }
        Mock -CommandName Set-PSITSocCase -MockWith {
            [PSCustomObject]@{ CaseId = 'PSIT-SOC-1'; Tenant = 'contoso.test'; AssignedTo = 'n1@partner.test' }
        }
        Mock -CommandName Get-Tenants -MockWith {
            @([PSCustomObject]@{ defaultDomainName = 'contoso.test' })
        }
    }

    It 'refuses the second click: the case names who already holds it' {
        Mock -CommandName Get-PSITSocCase -MockWith {
            [PSCustomObject]@{ CaseId = 'PSIT-SOC-1'; AssignedTo = 'collegue@partner.test' }
        }

        $Response = Invoke-PSITExecSocCase -Request (New-CaseRequest -Body @{ tenantFilter = 'contoso.test'; CaseId = 'PSIT-SOC-1'; TakeOwnership = $true }) -TriggerMetadata $null

        $Response.StatusCode | Should -Be ([HttpStatusCode]::Conflict)
        $Response.Body.Results | Should -Match 'collegue@partner.test'
        Should -Invoke Set-PSITSocCase -Times 0
    }

    It 'lets an unassigned case be taken, and re-taking your own is idempotent' {
        Mock -CommandName Get-PSITSocCase -MockWith {
            [PSCustomObject]@{ CaseId = 'PSIT-SOC-1'; AssignedTo = '' }
        }
        $Free = Invoke-PSITExecSocCase -Request (New-CaseRequest -Body @{ tenantFilter = 'contoso.test'; CaseId = 'PSIT-SOC-1'; TakeOwnership = $true }) -TriggerMetadata $null
        $Free.StatusCode | Should -Be ([HttpStatusCode]::OK)

        Mock -CommandName Get-PSITSocCase -MockWith {
            [PSCustomObject]@{ CaseId = 'PSIT-SOC-1'; AssignedTo = 'analyste@partner.test' }
        }
        # New-CaseRequest's harness analyst is analyste@partner.test.
        $Own = Invoke-PSITExecSocCase -Request (New-CaseRequest -Body @{ tenantFilter = 'contoso.test'; CaseId = 'PSIT-SOC-1'; TakeOwnership = $true }) -TriggerMetadata $null
        $Own.StatusCode | Should -Be ([HttpStatusCode]::OK)
    }
}
