function Get-PSITSocMetrics {
    <#
    .SYNOPSIS
        Aggregates dossiers into the numbers the steering screen and the monthly report quote.

    .DESCRIPTION
        Pure aggregation over already-fetched dossiers: counts by verdict, status, severity, type
        and tenant, a monthly series, and the three operational delays (creation to first take,
        to first verdict, to closure) as medians. Medians, not means: one dossier left open over
        a holiday must not swallow the story of the forty others.

        Which tenants the caller may count is access control and belongs to the endpoint; this
        function measures whatever it is handed. Time to verdict is measured to the FIRST verdict
        (a requalification is a correction, not a slower analyst), and time to take to the first
        move into investigation, which is what the queue's 'Prendre en charge' writes.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        # The dossiers to measure, already narrowed to what the caller may see.
        [AllowEmptyCollection()]
        [object[]]$Cases = @()
    )

    $ParseUtc = {
        param($Value)
        if ([string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
        try { return [datetime]::Parse([string]$Value, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal) } catch { return $null }
    }
    $Median = {
        param([double[]]$Values)
        if (-not $Values -or $Values.Count -eq 0) { return $null }
        $Sorted = @($Values | Sort-Object)
        $Middle = [math]::Floor($Sorted.Count / 2)
        if ($Sorted.Count % 2 -eq 1) { return [math]::Round($Sorted[$Middle]) }
        return [math]::Round(($Sorted[$Middle - 1] + $Sorted[$Middle]) / 2)
    }

    $ByVerdict = @{}
    $ByStatus = @{}
    $BySeverity = @{}
    $ByType = @{}
    $ByTenant = @{}
    $ByMonth = @{}
    $TakeMinutes = [System.Collections.Generic.List[double]]::new()
    $VerdictMinutes = [System.Collections.Generic.List[double]]::new()
    $CloseMinutes = [System.Collections.Generic.List[double]]::new()
    $OpenCount = 0

    foreach ($Case in @($Cases | Where-Object { $_ })) {
        $Status = [string]$Case.Status
        # 'none' is a bucket, not an absence: the screen must say how many dossiers still await
        # a verdict, and dropping them would inflate every rate computed against the total.
        $Verdict = [string]$Case.Qualification.Verdict
        if ([string]::IsNullOrWhiteSpace($Verdict)) { $Verdict = 'none' }
        $Tenant = [string]$Case.Tenant
        $Severity = if ([string]::IsNullOrWhiteSpace([string]$Case.Severity)) { 'none' } else { [string]$Case.Severity }
        $TypeKey = if ($null -ne $Case.TypeId) { [string]$Case.TypeId } else { 'none' }

        $ByVerdict[$Verdict] = ([int]$ByVerdict[$Verdict]) + 1
        $ByStatus[$Status] = ([int]$ByStatus[$Status]) + 1
        $BySeverity[$Severity] = ([int]$BySeverity[$Severity]) + 1
        if ($Status -ne 'closed') { $OpenCount++ }

        if (-not $ByType.ContainsKey($TypeKey)) {
            $ByType[$TypeKey] = @{ Count = 0; Qualified = 0; TruePositives = 0; BenignTruePositives = 0; FalsePositives = 0; Undetermined = 0 }
        }
        $Type = $ByType[$TypeKey]
        $Type.Count++
        switch ($Verdict) {
            'true-positive' { $Type.Qualified++; $Type.TruePositives++ }
            'benign-true-positive' { $Type.Qualified++; $Type.BenignTruePositives++ }
            'false-positive' { $Type.Qualified++; $Type.FalsePositives++ }
            'undetermined' { $Type.Qualified++; $Type.Undetermined++ }
        }

        if (-not $ByTenant.ContainsKey($Tenant)) {
            $ByTenant[$Tenant] = @{ Count = 0; Open = 0; TruePositives = 0 }
        }
        $ByTenant[$Tenant].Count++
        if ($Status -ne 'closed') { $ByTenant[$Tenant].Open++ }
        if ($Verdict -eq 'true-positive') { $ByTenant[$Tenant].TruePositives++ }

        $Created = & $ParseUtc $Case.CreatedUtc
        if ($Created) {
            $Month = $Created.ToString('yyyy-MM')
            if (-not $ByMonth.ContainsKey($Month)) {
                $ByMonth[$Month] = @{ Count = 0; TruePositives = 0; FalsePositives = 0 }
            }
            $ByMonth[$Month].Count++
            if ($Verdict -eq 'true-positive') { $ByMonth[$Month].TruePositives++ }
            if ($Verdict -eq 'false-positive') { $ByMonth[$Month].FalsePositives++ }

            # Time to take: the first move into investigation, whichever entry wrote it.
            $Taken = @($Case.ActionLog | Where-Object { [string]$_.Action -eq 'status' -and [string]$_.Detail -eq 'investigating' } |
                    ForEach-Object { & $ParseUtc $_.Utc } | Where-Object { $_ } | Sort-Object | Select-Object -First 1)
            if ($Taken.Count -gt 0 -and $Taken[0] -ge $Created) {
                $TakeMinutes.Add(($Taken[0] - $Created).TotalMinutes)
            }

            # Time to verdict: the FIRST one posed, including those later corrected.
            $Decided = @(@($Case.Qualification.PreviousVerdicts) + @($Case.Qualification) |
                    Where-Object { $_ } | ForEach-Object { & $ParseUtc $_.DecidedUtc } | Where-Object { $_ } |
                    Sort-Object | Select-Object -First 1)
            if ($Decided.Count -gt 0 -and $Decided[0] -ge $Created) {
                $VerdictMinutes.Add(($Decided[0] - $Created).TotalMinutes)
            }

            if ($Status -eq 'closed') {
                $Closed = & $ParseUtc $Case.ClosedUtc
                if ($Closed -and $Closed -ge $Created) {
                    $CloseMinutes.Add(($Closed - $Created).TotalMinutes)
                }
            }
        }
    }

    [pscustomobject]@{
        CaseCount = @($Cases | Where-Object { $_ }).Count
        OpenCount = $OpenCount
        ByVerdict = @($ByVerdict.GetEnumerator() | Sort-Object -Property Value -Descending | ForEach-Object {
                [pscustomobject]@{ Verdict = $_.Key; Count = $_.Value }
            })
        ByStatus  = @($ByStatus.GetEnumerator() | Sort-Object -Property Value -Descending | ForEach-Object {
                [pscustomobject]@{ Status = $_.Key; Count = $_.Value }
            })
        BySeverity = @($BySeverity.GetEnumerator() | Sort-Object -Property Value -Descending | ForEach-Object {
                [pscustomobject]@{ Severity = $_.Key; Count = $_.Value }
            })
        ByType    = @($ByType.GetEnumerator() | Sort-Object -Property { $_.Value.Count } -Descending | ForEach-Object {
                $Entry = $_.Value
                [pscustomobject]@{
                    TypeId              = if ($_.Key -match '^\d+$') { [int]$_.Key } else { $null }
                    Count               = [int]$Entry.Count
                    Qualified           = [int]$Entry.Qualified
                    TruePositives       = [int]$Entry.TruePositives
                    BenignTruePositives = [int]$Entry.BenignTruePositives
                    FalsePositives      = [int]$Entry.FalsePositives
                    Undetermined        = [int]$Entry.Undetermined
                    # Rate over the qualified only: unqualified dossiers are not yet an answer.
                    FpRatePercent       = if ($Entry.Qualified -gt 0) { [int][math]::Round(100 * $Entry.FalsePositives / $Entry.Qualified) } else { $null }
                }
            })
        ByTenant  = @($ByTenant.GetEnumerator() | Sort-Object -Property { $_.Value.Count } -Descending | ForEach-Object {
                [pscustomobject]@{
                    Tenant        = $_.Key
                    Count         = [int]$_.Value.Count
                    Open          = [int]$_.Value.Open
                    TruePositives = [int]$_.Value.TruePositives
                }
            })
        ByMonth   = @($ByMonth.GetEnumerator() | Sort-Object -Property Key | ForEach-Object {
                [pscustomobject]@{
                    Month          = $_.Key
                    Count          = [int]$_.Value.Count
                    TruePositives  = [int]$_.Value.TruePositives
                    FalsePositives = [int]$_.Value.FalsePositives
                }
            })
        Delays    = [pscustomobject]@{
            TakeMedianMinutes    = & $Median $TakeMinutes.ToArray()
            TakeCount            = $TakeMinutes.Count
            VerdictMedianMinutes = & $Median $VerdictMinutes.ToArray()
            VerdictCount         = $VerdictMinutes.Count
            CloseMedianMinutes   = & $Median $CloseMinutes.ToArray()
            CloseCount           = $CloseMinutes.Count
        }
    }
}
