function Set-PSITBecTriage {
    <#
    .SYNOPSIS
        Records an analyst's determinations on the BEC signals of one mailbox.

    .DESCRIPTION
        The collection can prove that 22 sign-ins succeeded from an address in Italy. It cannot
        know whether the user was in Italy. That fact lives with a human, so it is captured here:
        one row per investigated mailbox, holding a determination per signal with who decided,
        when, and on what grounds.

        Determinations are merged, not replaced: two analysts answering different questions on the
        same mailbox must not overwrite each other, and re-answering one signal keeps the history
        of the previous answer in PreviousVerdicts so a changed mind stays visible.

        Verdicts are deliberately three-valued. 'undetermined' is a real answer - the user is
        unreachable, the question stands - and it is what lets a report ship honestly instead of
        defaulting to a level nobody can defend.

    .PARAMETER Determinations
        Array of objects carrying SignalId, Verdict (expected|unexpected|undetermined) and an
        optional Justification.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,

        [Parameter(Mandatory = $true)]
        [string]$UserId,

        [string]$UserPrincipalName,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        $Determinations,

        [Parameter(Mandatory = $true)]
        [string]$Analyst
    )

    $ValidVerdicts = @('expected', 'unexpected', 'undetermined')
    $Table = Get-CippTable -tablename 'PSITBecTriage'
    $Existing = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$TenantFilter' and RowKey eq '$UserId'"

    $Current = @{}
    if ($Existing.Determinations) {
        try {
            $Parsed = $Existing.Determinations | ConvertFrom-Json -ErrorAction Stop
            foreach ($Entry in @($Parsed)) {
                if ($Entry.SignalId) { $Current[[string]$Entry.SignalId] = $Entry }
            }
        } catch {
            Write-Information "Existing triage for $UserId could not be parsed and is being replaced: $($_.Exception.Message)"
        }
    }

    $Now = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    foreach ($Determination in @($Determinations)) {
        $SignalId = [string]$Determination.SignalId
        if ([string]::IsNullOrWhiteSpace($SignalId)) { continue }

        $Verdict = [string]$Determination.Verdict
        if ($Verdict -notin $ValidVerdicts) {
            throw "Invalid verdict '$Verdict' for signal '$SignalId'. Expected one of: $($ValidVerdicts -join ', ')."
        }

        $Previous = $Current[$SignalId]
        $History = [System.Collections.Generic.List[object]]::new()
        if ($Previous) {
            foreach ($Old in @($Previous.PreviousVerdicts)) { if ($Old) { $History.Add($Old) } }
            # Only keep a history entry when the answer actually changed, otherwise a re-save on
            # the same verdict would pile up identical rows.
            if ([string]$Previous.Verdict -ne $Verdict -or [string]$Previous.Justification -ne [string]$Determination.Justification) {
                $History.Add([pscustomobject]@{
                        Verdict       = $Previous.Verdict
                        Justification = $Previous.Justification
                        Analyst       = $Previous.Analyst
                        DecidedUtc    = $Previous.DecidedUtc
                    })
            }
        }

        $Current[$SignalId] = [pscustomobject]@{
            SignalId         = $SignalId
            Verdict          = $Verdict
            Justification    = [string]$Determination.Justification
            Analyst          = $Analyst
            DecidedUtc       = $Now
            PreviousVerdicts = @($History)
        }
    }

    $Payload = @($Current.Values | Sort-Object -Property SignalId)
    $Entity = @{
        PartitionKey      = $TenantFilter
        RowKey            = $UserId
        UserPrincipalName = [string]$UserPrincipalName
        Determinations    = [string]($Payload | ConvertTo-Json -Depth 8 -Compress -AsArray)
        UpdatedBy         = $Analyst
        UpdatedUtc        = $Now
    }
    $null = Add-CIPPAzDataTableEntity @Table -Entity $Entity -Force

    Write-LogMessage -API 'PSITBecTriage' -tenant $TenantFilter -message "BEC triage updated for $($UserPrincipalName ?? $UserId) by $Analyst ($(@($Determinations).Count) signal(s))" -sev Info

    return [pscustomobject]@{
        TenantFilter      = $TenantFilter
        UserId            = $UserId
        UserPrincipalName = $UserPrincipalName
        Determinations    = $Payload
        UpdatedBy         = $Analyst
        UpdatedUtc        = $Now
    }
}
