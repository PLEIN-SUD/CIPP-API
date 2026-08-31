# Pester tests for Invoke-PSITExecCaseAuditSearch.
#
# Same doctrine as the download endpoint it generalises: the panel polls, so a poll must never
# open a search; a second Start must never open a second one; a relaunch keeps the search a
# report may already have quoted; and the summary is captured on the dossier at the first
# finished read, because the search expires with the tenant's journal.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $FunctionPath = Get-ChildItem -Path (Join-Path $RepoRoot 'Modules') -Recurse -Filter 'Invoke-PSITExecCaseAuditSearch.ps1' -File -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
    if (-not $FunctionPath) { throw 'Could not locate Invoke-PSITExecCaseAuditSearch.ps1 under Modules/' }

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
    function Write-LogMessage { param($headers, $API, $tenant, $message, $sev, $LogData) }
    function Get-CippException { param($Exception) [PSCustomObject]@{ NormalizedError = [string]$Exception } }
    function Get-PSITSocCase { param($TenantFilter, $CaseId, $Status, $Source, $ExternalRef) }
    function Set-PSITSocCase { param($TenantFilter, $CaseId, $Analyst, $Evidence, $LogAction) }
    function Get-PSITAuditSearchKind { param($TypeId) }
    function Start-PSITCaseAuditSearch { param($TenantFilter, $TypeId, $UserPrincipalName, $CaseId, $Analyst, $AroundUtc, $HoursBefore, $HoursAfter, $Previous) }
    function Get-PSITCaseAuditSearch { param($TenantFilter, $SearchId) }

    . $FunctionPath

    function New-CaseAuditRequest {
        param([hashtable]$Body)
        @{ Headers = @{}; Params = @{ CIPPEndpoint = 'PSITExecCaseAuditSearch' }; Query = @{}; Body = ([PSCustomObject]$Body) }
    }
}

Describe 'Invoke-PSITExecCaseAuditSearch' {
    BeforeEach {
        Mock -CommandName Write-LogMessage -MockWith { }
        Mock -CommandName Set-PSITSocCase -MockWith { }
        Mock -CommandName Get-PSITAuditSearchKind -MockWith {
            [PSCustomObject]@{ Key = 'mailbox-rules'; Label = 'règles de boîte'; RecordTypes = @('exchangeAdmin'); Operations = @('New-InboxRule') }
        }
        Mock -CommandName Get-PSITCaseAuditSearch -MockWith {
            [PSCustomObject]@{ SearchId = $SearchId; Status = 'succeeded'; Running = $false; Records = @(); Summary = [PSCustomObject]@{ EventCount = 0 }; Warnings = @() }
        }
        Mock -CommandName Start-PSITCaseAuditSearch -MockWith {
            [PSCustomObject]@{
                SearchId    = 'search-new'
                Kind        = 'mailbox-rules'
                StartUtc    = '2026-08-26T15:27:00.0000000Z'
                EndUtc      = '2026-08-28T19:27:00.0000000Z'
                LaunchedUtc = '2026-08-29T08:00:00.0000000Z'
                Status      = 'running'
            }
        }
        # A type 5 dossier that names a user and has no search filed yet.
        Mock -CommandName Get-PSITSocCase -MockWith {
            [PSCustomObject]@{
                CaseId     = 'PSIT-SOC-1'
                Tenant     = 'client.test'
                TypeId     = 5
                CreatedUtc = '2026-08-28T15:27:00Z'
                Entities   = [PSCustomObject]@{ upn = 'y.exemple@client.test' }
                Evidence   = [PSCustomObject]@{}
            }
        }
    }

    It 'reads without starting: a poll must not open a search' {
        $Result = Invoke-PSITExecCaseAuditSearch -Request (New-CaseAuditRequest -Body @{ tenantFilter = 'client.test'; CaseId = 'PSIT-SOC-1' }) -TriggerMetadata $null

        $Result.StatusCode | Should -Be ([HttpStatusCode]::OK)
        $Result.Body.Started | Should -BeFalse
        Should -Invoke Start-PSITCaseAuditSearch -Times 0
    }

    It 'starts when asked, with the dossier type and anchored on the dossier rather than on now' {
        $Result = Invoke-PSITExecCaseAuditSearch -Request (New-CaseAuditRequest -Body @{ tenantFilter = 'client.test'; CaseId = 'PSIT-SOC-1'; Start = $true }) -TriggerMetadata $null

        $Result.StatusCode | Should -Be ([HttpStatusCode]::OK)
        $Result.Body.Started | Should -BeTrue
        Should -Invoke Start-PSITCaseAuditSearch -Times 1 -ParameterFilter {
            $TypeId -eq 5 -and $AroundUtc -eq '2026-08-28T15:27:00Z' -and $UserPrincipalName -eq 'y.exemple@client.test'
        }
    }

    It 'journals the search with its kind and the window it covers' {
        $null = Invoke-PSITExecCaseAuditSearch -Request (New-CaseAuditRequest -Body @{ tenantFilter = 'client.test'; CaseId = 'PSIT-SOC-1'; Start = $true }) -TriggerMetadata $null

        Should -Invoke Set-PSITSocCase -Times 1 -ParameterFilter {
            $LogAction.Action -eq 'audit-search' -and $LogAction.Detail -match 'mailbox-rules' -and $LogAction.Detail -match '26/08/2026'
        }
    }

    It 'answers 400 for a type that has no audit search, instead of inventing one' {
        Mock -CommandName Get-PSITAuditSearchKind -MockWith { $null }

        $Result = Invoke-PSITExecCaseAuditSearch -Request (New-CaseAuditRequest -Body @{ tenantFilter = 'client.test'; CaseId = 'PSIT-SOC-1'; Start = $true }) -TriggerMetadata $null

        $Result.StatusCode | Should -Be ([HttpStatusCode]::BadRequest)
        Should -Invoke Start-PSITCaseAuditSearch -Times 0
    }

    It 'reuses the filed search instead of opening a second one' {
        Mock -CommandName Get-PSITSocCase -MockWith {
            [PSCustomObject]@{
                CaseId   = 'PSIT-SOC-1'
                Tenant   = 'client.test'
                TypeId   = 5
                Entities = [PSCustomObject]@{ upn = 'y.exemple@client.test' }
                Evidence = [PSCustomObject]@{ audit = [PSCustomObject]@{ kind = 'mailbox-rules'; searchId = 'search-old'; user = 'y.exemple@client.test'; startUtc = '2026-08-26T15:27:00Z'; endUtc = '2026-08-28T19:27:00Z' } }
            }
        }

        $Result = Invoke-PSITExecCaseAuditSearch -Request (New-CaseAuditRequest -Body @{ tenantFilter = 'client.test'; CaseId = 'PSIT-SOC-1'; Start = $true }) -TriggerMetadata $null

        Should -Invoke Start-PSITCaseAuditSearch -Times 0
        Should -Invoke Get-PSITCaseAuditSearch -Times 1 -ParameterFilter { $SearchId -eq 'search-old' }
        $Result.Body.Window.StartUtc | Should -Be '2026-08-26T15:27:00Z'
        $Result.Body.Window.Kind | Should -Be 'mailbox-rules'
    }

    It 'hands the previous search to a relaunch, so the widened window does not erase it' {
        Mock -CommandName Get-PSITSocCase -MockWith {
            [PSCustomObject]@{
                CaseId     = 'PSIT-SOC-1'
                Tenant     = 'client.test'
                TypeId     = 5
                CreatedUtc = '2026-08-28T15:27:00Z'
                Entities   = [PSCustomObject]@{ upn = 'y.exemple@client.test' }
                Evidence   = [PSCustomObject]@{ audit = [PSCustomObject]@{ searchId = 'search-old' } }
            }
        }

        $null = Invoke-PSITExecCaseAuditSearch -Request (New-CaseAuditRequest -Body @{ tenantFilter = 'client.test'; CaseId = 'PSIT-SOC-1'; Restart = $true; HoursBefore = '168' }) -TriggerMetadata $null

        Should -Invoke Start-PSITCaseAuditSearch -Times 1 -ParameterFilter {
            $Previous.searchId -eq 'search-old' -and $HoursBefore -eq 168
        }
    }

    It 'captures the summary on the dossier at the first finished read' {
        Mock -CommandName Get-PSITSocCase -MockWith {
            [PSCustomObject]@{
                CaseId   = 'PSIT-SOC-1'
                Tenant   = 'client.test'
                TypeId   = 5
                Entities = [PSCustomObject]@{ upn = 'y.exemple@client.test' }
                Evidence = [PSCustomObject]@{ audit = [PSCustomObject]@{ kind = 'mailbox-rules'; searchId = 'search-old'; user = 'y.exemple@client.test' } }
            }
        }
        Mock -CommandName Get-PSITCaseAuditSearch -MockWith {
            [PSCustomObject]@{ SearchId = 'search-old'; Status = 'succeeded'; Running = $false; Records = @(); Summary = [PSCustomObject]@{ EventCount = 3 }; Warnings = @() }
        }

        $null = Invoke-PSITExecCaseAuditSearch -Request (New-CaseAuditRequest -Body @{ tenantFilter = 'client.test'; CaseId = 'PSIT-SOC-1' }) -TriggerMetadata $null

        Should -Invoke Set-PSITSocCase -Times 1 -ParameterFilter {
            $Evidence.audit.summary.EventCount -eq 3 -and $Evidence.audit.searchId -eq 'search-old'
        }
    }

    It 'does not re-capture a summary the dossier already holds' {
        # The first capture describes what the investigation saw; a later, emptier read of an
        # expiring search must never overwrite it.
        Mock -CommandName Get-PSITSocCase -MockWith {
            [PSCustomObject]@{
                CaseId   = 'PSIT-SOC-1'
                Tenant   = 'client.test'
                TypeId   = 5
                Entities = [PSCustomObject]@{ upn = 'y.exemple@client.test' }
                Evidence = [PSCustomObject]@{ audit = [PSCustomObject]@{ searchId = 'search-old'; summary = [PSCustomObject]@{ EventCount = 12 } } }
            }
        }
        Mock -CommandName Get-PSITCaseAuditSearch -MockWith {
            [PSCustomObject]@{ SearchId = 'search-old'; Status = 'succeeded'; Running = $false; Records = @(); Summary = [PSCustomObject]@{ EventCount = 0 }; Warnings = @() }
        }

        $null = Invoke-PSITExecCaseAuditSearch -Request (New-CaseAuditRequest -Body @{ tenantFilter = 'client.test'; CaseId = 'PSIT-SOC-1' }) -TriggerMetadata $null

        Should -Invoke Set-PSITSocCase -Times 0
    }

    It 'refuses a dossier that names nobody, rather than searching the whole tenant' {
        Mock -CommandName Get-PSITSocCase -MockWith {
            [PSCustomObject]@{ CaseId = 'PSIT-SOC-1'; Tenant = 'client.test'; TypeId = 5; Entities = [PSCustomObject]@{}; Evidence = [PSCustomObject]@{} }
        }

        $Result = Invoke-PSITExecCaseAuditSearch -Request (New-CaseAuditRequest -Body @{ tenantFilter = 'client.test'; CaseId = 'PSIT-SOC-1'; Start = $true }) -TriggerMetadata $null

        $Result.StatusCode | Should -Be ([HttpStatusCode]::BadRequest)
        Should -Invoke Start-PSITCaseAuditSearch -Times 0
    }

    It 'answers 404 for a dossier that does not exist on this tenant' {
        Mock -CommandName Get-PSITSocCase -MockWith { @() }

        $Result = Invoke-PSITExecCaseAuditSearch -Request (New-CaseAuditRequest -Body @{ tenantFilter = 'client.test'; CaseId = 'PSIT-SOC-9'; Start = $true }) -TriggerMetadata $null

        $Result.StatusCode | Should -Be ([HttpStatusCode]::NotFound)
    }

    It 'requires both the tenant and the dossier' {
        $Result = Invoke-PSITExecCaseAuditSearch -Request (New-CaseAuditRequest -Body @{ CaseId = 'PSIT-SOC-1' }) -TriggerMetadata $null

        $Result.StatusCode | Should -Be ([HttpStatusCode]::BadRequest)
        Should -Invoke Get-PSITSocCase -Times 0
    }
}
