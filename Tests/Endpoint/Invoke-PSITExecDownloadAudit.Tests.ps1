# Pester tests for Invoke-PSITExecDownloadAudit.
#
# The panel polls this endpoint every few seconds while a search runs. That is the whole reason
# reading and starting are separate verbs here, and what these tests pin: a poll must never open a
# search, a second Start must never open a second one, and a relaunch must keep the search a
# report may already have quoted.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $FunctionPath = Get-ChildItem -Path (Join-Path $RepoRoot 'Modules') -Recurse -Filter 'Invoke-PSITExecDownloadAudit.ps1' -File -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
    if (-not $FunctionPath) { throw 'Could not locate Invoke-PSITExecDownloadAudit.ps1 under Modules/' }

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
    function Start-PSITDownloadAudit { param($TenantFilter, $UserPrincipalName, $CaseId, $Analyst, $AroundUtc, $HoursBefore, $HoursAfter, $Previous) }
    function Get-PSITDownloadAudit { param($TenantFilter, $SearchId) }

    . $FunctionPath

    function New-AuditRequest {
        param([hashtable]$Body)
        @{ Headers = @{}; Params = @{ CIPPEndpoint = 'PSITExecDownloadAudit' }; Query = @{}; Body = ([PSCustomObject]$Body) }
    }
}

Describe 'Invoke-PSITExecDownloadAudit' {
    BeforeEach {
        Mock -CommandName Write-LogMessage -MockWith { }
        Mock -CommandName Set-PSITSocCase -MockWith { }
        Mock -CommandName Get-PSITDownloadAudit -MockWith {
            [PSCustomObject]@{ SearchId = $SearchId; Status = 'succeeded'; Running = $false; Records = @(); Summary = [PSCustomObject]@{ FileCount = 0 }; Warnings = @() }
        }
        Mock -CommandName Start-PSITDownloadAudit -MockWith {
            [PSCustomObject]@{
                SearchId    = 'search-new'
                StartUtc    = '2026-08-28T03:27:00.0000000Z'
                EndUtc      = '2026-08-28T19:27:00.0000000Z'
                LaunchedUtc = '2026-08-29T08:00:00.0000000Z'
                Status      = 'running'
            }
        }
        # A dossier that names a user and has no search filed yet.
        Mock -CommandName Get-PSITSocCase -MockWith {
            [PSCustomObject]@{
                CaseId     = 'PSIT-SOC-1'
                Tenant     = 'client.test'
                CreatedUtc = '2026-08-28T15:27:00Z'
                Entities   = [PSCustomObject]@{ upn = 'y.exemple@client.test' }
                Evidence   = [PSCustomObject]@{}
            }
        }
    }

    It 'reads without starting: a poll must not open a search' {
        $Result = Invoke-PSITExecDownloadAudit -Request (New-AuditRequest -Body @{ tenantFilter = 'client.test'; CaseId = 'PSIT-SOC-1' }) -TriggerMetadata $null

        $Result.StatusCode | Should -Be ([HttpStatusCode]::OK)
        $Result.Body.Started | Should -BeFalse
        Should -Invoke Start-PSITDownloadAudit -Times 0
    }

    It 'starts when asked, anchored on the dossier rather than on now' {
        $Result = Invoke-PSITExecDownloadAudit -Request (New-AuditRequest -Body @{ tenantFilter = 'client.test'; CaseId = 'PSIT-SOC-1'; Start = $true }) -TriggerMetadata $null

        $Result.StatusCode | Should -Be ([HttpStatusCode]::OK)
        $Result.Body.Started | Should -BeTrue
        Should -Invoke Start-PSITDownloadAudit -Times 1 -ParameterFilter {
            $AroundUtc -eq '2026-08-28T15:27:00Z' -and $UserPrincipalName -eq 'y.exemple@client.test'
        }
    }

    It 'journals the search with the window it covers' {
        # "Why does the report say 370 files?" is answered by the journal, or by nothing.
        $null = Invoke-PSITExecDownloadAudit -Request (New-AuditRequest -Body @{ tenantFilter = 'client.test'; CaseId = 'PSIT-SOC-1'; Start = $true }) -TriggerMetadata $null

        Should -Invoke Set-PSITSocCase -Times 1 -ParameterFilter {
            $LogAction.Action -eq 'audit-search' -and $LogAction.Detail -match '28/08/2026'
        }
    }

    It 'reuses the filed search instead of opening a second one' {
        Mock -CommandName Get-PSITSocCase -MockWith {
            [PSCustomObject]@{
                CaseId   = 'PSIT-SOC-1'
                Tenant   = 'client.test'
                Entities = [PSCustomObject]@{ upn = 'y.exemple@client.test' }
                Evidence = [PSCustomObject]@{ download = [PSCustomObject]@{ searchId = 'search-old'; user = 'y.exemple@client.test'; startUtc = '2026-08-28T03:27:00Z'; endUtc = '2026-08-28T19:27:00Z' } }
            }
        }

        $Result = Invoke-PSITExecDownloadAudit -Request (New-AuditRequest -Body @{ tenantFilter = 'client.test'; CaseId = 'PSIT-SOC-1'; Start = $true }) -TriggerMetadata $null

        Should -Invoke Start-PSITDownloadAudit -Times 0
        Should -Invoke Get-PSITDownloadAudit -Times 1 -ParameterFilter { $SearchId -eq 'search-old' }
        $Result.Body.Window.StartUtc | Should -Be '2026-08-28T03:27:00Z'
    }

    It 'hands the previous search to a relaunch, so the widened window does not erase it' {
        Mock -CommandName Get-PSITSocCase -MockWith {
            [PSCustomObject]@{
                CaseId     = 'PSIT-SOC-1'
                Tenant     = 'client.test'
                CreatedUtc = '2026-08-28T15:27:00Z'
                Entities   = [PSCustomObject]@{ upn = 'y.exemple@client.test' }
                Evidence   = [PSCustomObject]@{ download = [PSCustomObject]@{ searchId = 'search-old' } }
            }
        }

        $null = Invoke-PSITExecDownloadAudit -Request (New-AuditRequest -Body @{ tenantFilter = 'client.test'; CaseId = 'PSIT-SOC-1'; Restart = $true; HoursBefore = '168' }) -TriggerMetadata $null

        Should -Invoke Start-PSITDownloadAudit -Times 1 -ParameterFilter {
            $Previous.searchId -eq 'search-old' -and $HoursBefore -eq 168
        }
    }

    It 'captures the summary on the dossier at the first finished read' {
        # The search expires with the tenant's journal; the report quotes these numbers, so they
        # must outlive their source.
        Mock -CommandName Get-PSITSocCase -MockWith {
            [PSCustomObject]@{
                CaseId   = 'PSIT-SOC-1'
                Tenant   = 'client.test'
                Entities = [PSCustomObject]@{ upn = 'y.exemple@client.test' }
                Evidence = [PSCustomObject]@{ download = [PSCustomObject]@{ searchId = 'search-old'; user = 'y.exemple@client.test' } }
            }
        }
        Mock -CommandName Get-PSITDownloadAudit -MockWith {
            [PSCustomObject]@{ SearchId = 'search-old'; Status = 'succeeded'; Running = $false; Records = @(); Summary = [PSCustomObject]@{ FileCount = 3 }; Warnings = @() }
        }

        $null = Invoke-PSITExecDownloadAudit -Request (New-AuditRequest -Body @{ tenantFilter = 'client.test'; CaseId = 'PSIT-SOC-1' }) -TriggerMetadata $null

        Should -Invoke Set-PSITSocCase -Times 1 -ParameterFilter {
            $Evidence.download.summary.FileCount -eq 3 -and $Evidence.download.searchId -eq 'search-old'
        }
    }

    It 'does not re-capture a summary the dossier already holds' {
        # The first capture describes what the investigation saw; a later, emptier read of an
        # expiring search must never overwrite it.
        Mock -CommandName Get-PSITSocCase -MockWith {
            [PSCustomObject]@{
                CaseId   = 'PSIT-SOC-1'
                Tenant   = 'client.test'
                Entities = [PSCustomObject]@{ upn = 'y.exemple@client.test' }
                Evidence = [PSCustomObject]@{ download = [PSCustomObject]@{ searchId = 'search-old'; summary = [PSCustomObject]@{ FileCount = 370 } } }
            }
        }
        Mock -CommandName Get-PSITDownloadAudit -MockWith {
            [PSCustomObject]@{ SearchId = 'search-old'; Status = 'succeeded'; Running = $false; Records = @(); Summary = [PSCustomObject]@{ FileCount = 0 }; Warnings = @() }
        }

        $null = Invoke-PSITExecDownloadAudit -Request (New-AuditRequest -Body @{ tenantFilter = 'client.test'; CaseId = 'PSIT-SOC-1' }) -TriggerMetadata $null

        Should -Invoke Set-PSITSocCase -Times 0
    }

    It 'refuses a dossier that names nobody, rather than searching the whole tenant' {
        Mock -CommandName Get-PSITSocCase -MockWith {
            [PSCustomObject]@{ CaseId = 'PSIT-SOC-1'; Tenant = 'client.test'; Entities = [PSCustomObject]@{}; Evidence = [PSCustomObject]@{} }
        }

        $Result = Invoke-PSITExecDownloadAudit -Request (New-AuditRequest -Body @{ tenantFilter = 'client.test'; CaseId = 'PSIT-SOC-1'; Start = $true }) -TriggerMetadata $null

        $Result.StatusCode | Should -Be ([HttpStatusCode]::BadRequest)
        Should -Invoke Start-PSITDownloadAudit -Times 0
    }

    It 'answers 404 for a dossier that does not exist on this tenant' {
        Mock -CommandName Get-PSITSocCase -MockWith { @() }

        $Result = Invoke-PSITExecDownloadAudit -Request (New-AuditRequest -Body @{ tenantFilter = 'client.test'; CaseId = 'PSIT-SOC-9'; Start = $true }) -TriggerMetadata $null

        $Result.StatusCode | Should -Be ([HttpStatusCode]::NotFound)
    }

    It 'requires both the tenant and the dossier' {
        $Result = Invoke-PSITExecDownloadAudit -Request (New-AuditRequest -Body @{ CaseId = 'PSIT-SOC-1' }) -TriggerMetadata $null

        $Result.StatusCode | Should -Be ([HttpStatusCode]::BadRequest)
        Should -Invoke Get-PSITSocCase -Times 0
    }
}
