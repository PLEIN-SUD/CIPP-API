# Pester tests for Invoke-PSITExecSocEscalate.
#
# What they pin: the reassignment and the journal entry ARE the escalation; the mail is how the
# recipient learns of it. A failed mail therefore warns and never fails, and an escalation
# without a recipient or a reason is refused - an unexplained escalation is a hot potato.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $FunctionPath = Get-ChildItem -Path (Join-Path $RepoRoot 'Modules') -Recurse -Filter 'Invoke-PSITExecSocEscalate.ps1' -File -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
    if (-not $FunctionPath) { throw 'Could not locate Invoke-PSITExecSocEscalate.ps1 under Modules/' }

    class HttpResponseContext {
        [int]$StatusCode
        [object]$Body
    }
    $Accelerators = [PSObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')
    if (-not ('HttpStatusCode' -as [type])) {
        $Accelerators::Add('HttpStatusCode', [System.Net.HttpStatusCode])
    }

    function Get-PSITSocRequestValue { param($Value) return $Value }
    function Get-PSITBecAnalyst { param($Headers) return 'n1@partner.test' }
    function Write-LogMessage { param($headers, $API, $tenant, $message, $sev, $LogData) }
    function Get-CippException { param($Exception) [PSCustomObject]@{ NormalizedError = [string]$Exception } }
    function Set-PSITSocCase { param($TenantFilter, $CaseId, $Analyst, $AssignedTo, $LogAction) }
    function Get-CippTable { param($tablename) @{ Table = $tablename } }
    function Get-CIPPAzDataTableEntity { param($Table, $Filter) }
    function Send-CIPPAlert { param($Type, $Title, $HTMLContent, $JSONContent, $TenantFilter, $altEmail, $altWebhook, $APIName) }

    . $FunctionPath

    function New-EscalateRequest {
        param([hashtable]$Body)
        @{ Headers = @{}; Params = @{ CIPPEndpoint = 'PSITExecSocEscalate' }; Query = @{}; Body = ([PSCustomObject]$Body) }
    }
}

Describe 'Invoke-PSITExecSocEscalate' {
    BeforeEach {
        Mock -CommandName Write-LogMessage -MockWith { }
        Mock -CommandName Set-PSITSocCase -MockWith {
            [PSCustomObject]@{ CaseId = 'PSIT-SOC-1'; Tenant = 'client.test'; Title = 'Voyage impossible'; AssignedTo = $AssignedTo }
        }
        Mock -CommandName Get-CIPPAzDataTableEntity -MockWith { [PSCustomObject]@{ Value = 'cipp.example.test' } }
        Mock -CommandName Send-CIPPAlert -MockWith { }
    }

    It 'reassigns, journals the reason, and mails the recipient directly with the dossier link' {
        $Response = Invoke-PSITExecSocEscalate -Request (New-EscalateRequest -Body @{
                tenantFilter = 'client.test'; CaseId = 'PSIT-SOC-1'
                EscalateTo = 'senior@partner.test'; Reason = "AiTM suspecté, besoin d'un second regard"
            }) -TriggerMetadata $null

        $Response.StatusCode | Should -Be ([HttpStatusCode]::OK)
        Should -Invoke Set-PSITSocCase -Times 1 -ParameterFilter {
            $AssignedTo -eq 'senior@partner.test' -and $LogAction.Action -eq 'escalated' -and $LogAction.Detail -match 'AiTM'
        }
        # -altEmail bypasses the notification config on purpose: the escalation must reach its
        # recipient whether or not the portal's general notifications are set up.
        Should -Invoke Send-CIPPAlert -Times 1 -ParameterFilter {
            $Type -eq 'email' -and $altEmail -eq 'senior@partner.test' -and $HTMLContent -match 'security/soc/case\?caseId=PSIT-SOC-1'
        }
    }

    It 'a failed mail warns and never fails: the reassignment IS the escalation' {
        Mock -CommandName Send-CIPPAlert -MockWith { throw 'smtp down' }

        $Response = Invoke-PSITExecSocEscalate -Request (New-EscalateRequest -Body @{
                tenantFilter = 'client.test'; CaseId = 'PSIT-SOC-1'
                EscalateTo = 'senior@partner.test'; Reason = 'second regard'
            }) -TriggerMetadata $null

        $Response.StatusCode | Should -Be ([HttpStatusCode]::OK)
        $Response.Body.Warnings[0] | Should -Match 'prévenez-le autrement'
        Should -Invoke Set-PSITSocCase -Times 1
    }

    It 'refuses an escalation without recipient or reason' {
        $NoReason = Invoke-PSITExecSocEscalate -Request (New-EscalateRequest -Body @{
                tenantFilter = 'client.test'; CaseId = 'PSIT-SOC-1'; EscalateTo = 'senior@partner.test'
            }) -TriggerMetadata $null
        $NoReason.StatusCode | Should -Be ([HttpStatusCode]::BadRequest)

        $NoTarget = Invoke-PSITExecSocEscalate -Request (New-EscalateRequest -Body @{
                tenantFilter = 'client.test'; CaseId = 'PSIT-SOC-1'; Reason = 'second regard'
            }) -TriggerMetadata $null
        $NoTarget.StatusCode | Should -Be ([HttpStatusCode]::BadRequest)

        Should -Invoke Set-PSITSocCase -Times 0
    }
}
