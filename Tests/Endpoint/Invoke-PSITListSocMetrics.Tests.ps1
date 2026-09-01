# Pester tests for Invoke-PSITListSocMetrics.
#
# The numbers this endpoint answers go on a steering screen and into a monthly client report.
# What is pinned here: the caller's tenant narrowing applies BEFORE aggregation (a restricted
# role's numbers must only ever describe its own tenants), the period bounds apply on creation
# time, and the answer carries the window it measured - a count without its window means nothing.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $FunctionPath = Get-ChildItem -Path (Join-Path $RepoRoot 'Modules') -Recurse -Filter 'Invoke-PSITListSocMetrics.ps1' -File -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
    $MetricsPath = Get-ChildItem -Path (Join-Path $RepoRoot 'Modules') -Recurse -Filter 'Get-PSITSocMetrics.ps1' -File |
        Select-Object -First 1 -ExpandProperty FullName
    if (-not $FunctionPath -or -not $MetricsPath) { throw 'Could not locate the SOC metrics functions under Modules/' }

    # Azure Functions binding types do not exist outside the Functions host - fake them.
    class HttpResponseContext {
        [int]$StatusCode
        [object]$Body
    }
    $Accelerators = [PSObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')
    if (-not ('HttpStatusCode' -as [type])) {
        $Accelerators::Add('HttpStatusCode', [System.Net.HttpStatusCode])
    }

    function Write-LogMessage { param($headers, $API, $tenant, $message, $sev, $LogData) }
    function Get-CippException { param($Exception) [PSCustomObject]@{ NormalizedError = [string]$Exception } }
    function Get-PSITSocCase { param($TenantFilter, $CaseId, $Status, $Source, $ExternalRef) }

    # A pass-through that drops the marker tenant: what the narrowing does for a restricted
    # caller, without dragging in its AsyncLocal plumbing. Its own behaviour has its own tests.
    function Select-CippAllowedTenantData {
        param([Parameter(ValueFromPipeline)]$InputObject, $TenantProperty, [switch]$AllowPartner)
        process { if ([string]$InputObject.Tenant -ne 'forbidden.test') { $InputObject } }
    }

    # The real aggregation: the endpoint's answer is the reader's contract, so the shape asserted
    # below is the shape the front consumes.
    . $MetricsPath
    . $FunctionPath

    function New-MetricsRequest {
        param([hashtable]$Query = @{})
        @{ Headers = @{}; Params = @{ CIPPEndpoint = 'PSITListSocMetrics' }; Query = ([PSCustomObject]$Query); Body = $null }
    }

    $script:Rows = @(
        [pscustomobject]@{
            CaseId = 'PSIT-SOC-1'; Tenant = 'client.test'; TypeId = 2; Severity = 'P2'; Status = 'closed'
            CreatedUtc = '2026-08-10T08:00:00Z'; ClosedUtc = '2026-08-10T12:00:00Z'
            Qualification = [pscustomobject]@{ Verdict = 'true-positive'; DecidedUtc = '2026-08-10T09:00:00Z'; PreviousVerdicts = @() }
            ActionLog = @()
        }
        [pscustomobject]@{
            CaseId = 'PSIT-SOC-2'; Tenant = 'client.test'; TypeId = 5; Severity = 'P3'; Status = 'investigating'
            CreatedUtc = '2026-09-02T08:00:00Z'; ClosedUtc = ''
            Qualification = $null; ActionLog = @()
        }
        [pscustomobject]@{
            CaseId = 'PSIT-SOC-3'; Tenant = 'forbidden.test'; TypeId = 2; Severity = 'P1'; Status = 'new'
            CreatedUtc = '2026-08-15T08:00:00Z'; ClosedUtc = ''
            Qualification = $null; ActionLog = @()
        }
    )
}

Describe 'Invoke-PSITListSocMetrics' {
    BeforeEach {
        Mock -CommandName Write-LogMessage -MockWith { }
        Mock -CommandName Get-PSITSocCase -MockWith { $script:Rows }
    }

    It 'never counts a tenant the caller cannot see' {
        $Result = Invoke-PSITListSocMetrics -Request (New-MetricsRequest) -TriggerMetadata $null

        $Result.StatusCode | Should -Be ([HttpStatusCode]::OK)
        # Three rows exist; the forbidden tenant's dossier is not in any number.
        $Result.Body.CaseCount | Should -Be 2
        @($Result.Body.ByTenant | Where-Object { $_.Tenant -eq 'forbidden.test' }) | Should -HaveCount 0
        ($Result.Body.BySeverity | Where-Object { $_.Severity -eq 'P1' }) | Should -BeNullOrEmpty
    }

    It 'passes the tenant filter through to the read, and says which tenant it measured' {
        Mock -CommandName Get-PSITSocCase -MockWith { @($script:Rows | Where-Object { $_.Tenant -eq $TenantFilter }) }

        $Result = Invoke-PSITListSocMetrics -Request (New-MetricsRequest -Query @{ tenantFilter = 'client.test' }) -TriggerMetadata $null

        Should -Invoke Get-PSITSocCase -Times 1 -ParameterFilter { $TenantFilter -eq 'client.test' }
        $Result.Body.Window.Tenant | Should -Be 'client.test'
    }

    It 'treats AllTenants as the whole queue, not as a tenant name' {
        $null = Invoke-PSITListSocMetrics -Request (New-MetricsRequest -Query @{ tenantFilter = 'AllTenants' }) -TriggerMetadata $null

        Should -Invoke Get-PSITSocCase -Times 1 -ParameterFilter { -not $PSBoundParameters.ContainsKey('TenantFilter') }
    }

    It 'bounds the period on creation time, and answers the window it measured' {
        $Result = Invoke-PSITListSocMetrics -Request (New-MetricsRequest -Query @{
                StartUtc = '2026-08-01T00:00:00Z'; EndUtc = '2026-09-01T00:00:00Z'
            }) -TriggerMetadata $null

        # Only the August dossier of the allowed tenant is inside the window.
        $Result.Body.CaseCount | Should -Be 1
        $Result.Body.ByMonth[0].Month | Should -Be '2026-08'
        $Result.Body.Window.StartUtc | Should -Match '^2026-08-01'
        $Result.Body.Window.EndUtc | Should -Match '^2026-09-01'
    }

    It 'answers the failure in French rather than an empty set of numbers' {
        Mock -CommandName Get-PSITSocCase -MockWith { throw 'storage unreachable' }

        $Result = Invoke-PSITListSocMetrics -Request (New-MetricsRequest) -TriggerMetadata $null

        $Result.StatusCode | Should -Be ([HttpStatusCode]::InternalServerError)
        $Result.Body.Results | Should -Match "indicateurs n'ont pas pu"
    }
}
