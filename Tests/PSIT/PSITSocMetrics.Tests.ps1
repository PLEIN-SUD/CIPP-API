# Pester tests for the SOC metrics aggregation.
#
# These numbers end up in front of a client and in front of the team lead: what is pinned here is
# that they mean what they say. A dossier without a verdict is counted as awaiting one rather than
# dropped, the FP rate is computed over qualified dossiers only, the delays are medians measured
# to the FIRST verdict (a requalification is a correction, not a slower analyst), and an empty
# queue answers zeros and nulls rather than throwing.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $FunctionPath = Get-ChildItem -Path (Join-Path $RepoRoot 'Modules') -Recurse -Filter 'Get-PSITSocMetrics.ps1' -File |
        Select-Object -First 1 -ExpandProperty FullName
    if (-not $FunctionPath) { throw 'Could not locate Get-PSITSocMetrics.ps1 under Modules/' }

    . $FunctionPath

    # Three dossiers, shaped exactly as Get-PSITSocCase returns them.
    # A: type 2 true positive, taken after 30 min, qualified after 2 h, closed after a day.
    # B: type 2, first qualified TP after 40 min then corrected to FP two days later, closed
    #    after 4 h, taken after 10 min.
    # C: type 5, still investigating (taken after 50 min), no verdict yet.
    $script:CaseA = [pscustomobject]@{
        CaseId = 'PSIT-SOC-A'; Tenant = 'tenant1.test'; TypeId = 2; Severity = 'P2'
        Status = 'closed'; CreatedUtc = '2026-08-01T08:00:00Z'; ClosedUtc = '2026-08-02T08:00:00Z'
        Qualification = [pscustomobject]@{ Verdict = 'true-positive'; DecidedUtc = '2026-08-01T10:00:00Z'; PreviousVerdicts = @() }
        ActionLog = @(
            [pscustomobject]@{ Utc = '2026-08-01T08:00:00Z'; Analyst = 'system'; Action = 'created'; Detail = 'type 2' }
            [pscustomobject]@{ Utc = '2026-08-01T08:30:00Z'; Analyst = 'a@partner.test'; Action = 'status'; Detail = 'investigating' }
        )
    }
    $script:CaseB = [pscustomobject]@{
        CaseId = 'PSIT-SOC-B'; Tenant = 'tenant1.test'; TypeId = 2; Severity = 'P2'
        Status = 'closed'; CreatedUtc = '2026-08-03T08:00:00Z'; ClosedUtc = '2026-08-03T12:00:00Z'
        Qualification = [pscustomobject]@{
            Verdict = 'false-positive'; DecidedUtc = '2026-08-05T09:00:00Z'
            PreviousVerdicts = @([pscustomobject]@{ Verdict = 'true-positive'; DecidedUtc = '2026-08-03T08:40:00Z' })
        }
        ActionLog = @(
            [pscustomobject]@{ Utc = '2026-08-03T08:10:00Z'; Analyst = 'b@partner.test'; Action = 'status'; Detail = 'investigating' }
        )
    }
    $script:CaseC = [pscustomobject]@{
        CaseId = 'PSIT-SOC-C'; Tenant = 'tenant2.test'; TypeId = 5; Severity = 'P3'
        Status = 'investigating'; CreatedUtc = '2026-09-01T08:00:00Z'; ClosedUtc = ''
        Qualification = $null
        ActionLog = @(
            [pscustomobject]@{ Utc = '2026-09-01T08:50:00Z'; Analyst = 'a@partner.test'; Action = 'status'; Detail = 'investigating' }
        )
    }
    $script:AllCases = @($script:CaseA, $script:CaseB, $script:CaseC)
}

Describe 'Get-PSITSocMetrics' {
    It 'counts a dossier without a verdict as awaiting one, never drops it' {
        $Metrics = Get-PSITSocMetrics -Cases $script:AllCases

        $Metrics.CaseCount | Should -Be 3
        ($Metrics.ByVerdict | Where-Object { $_.Verdict -eq 'none' }).Count | Should -Be 1
        ($Metrics.ByVerdict | Where-Object { $_.Verdict -eq 'true-positive' }).Count | Should -Be 1
        ($Metrics.ByVerdict | Where-Object { $_.Verdict -eq 'false-positive' }).Count | Should -Be 1
    }

    It 'computes the FP rate over qualified dossiers only' {
        $Metrics = Get-PSITSocMetrics -Cases $script:AllCases

        $Type2 = $Metrics.ByType | Where-Object { $_.TypeId -eq 2 }
        $Type2.Count | Should -Be 2
        $Type2.Qualified | Should -Be 2
        $Type2.FpRatePercent | Should -Be 50
        # A type with no verdict yet has no rate, not a rate of zero.
        $Type5 = $Metrics.ByType | Where-Object { $_.TypeId -eq 5 }
        $Type5.Qualified | Should -Be 0
        $Type5.FpRatePercent | Should -BeNullOrEmpty
    }

    It 'measures the median delays: to take, to first verdict, to closure' {
        $Metrics = Get-PSITSocMetrics -Cases $script:AllCases

        # Take: 30, 10 and 50 minutes -> median 30.
        $Metrics.Delays.TakeMedianMinutes | Should -Be 30
        $Metrics.Delays.TakeCount | Should -Be 3
        # Verdict: 120 min (A) and 40 min (B, its FIRST verdict - the correction two days later
        # must not count as the analysis time). Median of the pair: 80.
        $Metrics.Delays.VerdictMedianMinutes | Should -Be 80
        $Metrics.Delays.VerdictCount | Should -Be 2
        # Close: 1440 min (A) and 240 min (B); C is open. Median: 840.
        $Metrics.Delays.CloseMedianMinutes | Should -Be 840
        $Metrics.Delays.CloseCount | Should -Be 2
    }

    It 'says who is still open, per tenant and in total' {
        $Metrics = Get-PSITSocMetrics -Cases $script:AllCases

        $Metrics.OpenCount | Should -Be 1
        $Tenant1 = $Metrics.ByTenant | Where-Object { $_.Tenant -eq 'tenant1.test' }
        $Tenant1.Count | Should -Be 2
        $Tenant1.Open | Should -Be 0
        $Tenant1.TruePositives | Should -Be 1
        ($Metrics.ByTenant | Where-Object { $_.Tenant -eq 'tenant2.test' }).Open | Should -Be 1
    }

    It 'buckets the monthly series on creation time, oldest first' {
        $Metrics = Get-PSITSocMetrics -Cases $script:AllCases

        $Metrics.ByMonth[0].Month | Should -Be '2026-08'
        $Metrics.ByMonth[0].Count | Should -Be 2
        $Metrics.ByMonth[0].TruePositives | Should -Be 1
        $Metrics.ByMonth[0].FalsePositives | Should -Be 1
        $Metrics.ByMonth[1].Month | Should -Be '2026-09'
        $Metrics.ByMonth[1].Count | Should -Be 1
    }

    It 'answers zeros and nulls for an empty queue rather than throwing' {
        $Metrics = Get-PSITSocMetrics -Cases @()

        $Metrics.CaseCount | Should -Be 0
        $Metrics.OpenCount | Should -Be 0
        $Metrics.ByType | Should -HaveCount 0
        $Metrics.Delays.TakeMedianMinutes | Should -BeNullOrEmpty
        $Metrics.Delays.VerdictMedianMinutes | Should -BeNullOrEmpty
        $Metrics.Delays.CloseMedianMinutes | Should -BeNullOrEmpty
    }

    It 'counts a dossier whose dates are unreadable, but keeps it out of the delays' {
        $Broken = [pscustomobject]@{
            CaseId = 'PSIT-SOC-X'; Tenant = 'tenant1.test'; TypeId = 2; Severity = 'P2'
            Status = 'closed'; CreatedUtc = 'pas-une-date'; ClosedUtc = '2026-08-02T08:00:00Z'
            Qualification = [pscustomobject]@{ Verdict = 'true-positive'; DecidedUtc = '2026-08-01T10:00:00Z'; PreviousVerdicts = @() }
            ActionLog = @()
        }

        $Metrics = Get-PSITSocMetrics -Cases @($Broken)

        $Metrics.CaseCount | Should -Be 1
        ($Metrics.ByVerdict | Where-Object { $_.Verdict -eq 'true-positive' }).Count | Should -Be 1
        $Metrics.Delays.CloseCount | Should -Be 0
    }
}

Describe 'Get-PSITSocMetrics, weekly series' {
    It 'buckets the weekly series on ISO weeks, oldest first' {
        # 2026-08-01 is a Saturday of ISO week 31; 2026-08-03 opens week 32; 2026-09-01 is week 36.
        $Cases = @(
            [pscustomobject]@{ CaseId = 'A'; Tenant = 't'; TypeId = 2; Severity = 'P2'; Status = 'closed'; CreatedUtc = '2026-08-01T08:00:00Z'; ClosedUtc = ''; Qualification = [pscustomobject]@{ Verdict = 'true-positive'; DecidedUtc = ''; PreviousVerdicts = @() }; ActionLog = @() }
            [pscustomobject]@{ CaseId = 'B'; Tenant = 't'; TypeId = 2; Severity = 'P2'; Status = 'new'; CreatedUtc = '2026-08-03T08:00:00Z'; ClosedUtc = ''; Qualification = $null; ActionLog = @() }
            [pscustomobject]@{ CaseId = 'C'; Tenant = 't'; TypeId = 2; Severity = 'P2'; Status = 'new'; CreatedUtc = '2026-09-01T08:00:00Z'; ClosedUtc = ''; Qualification = [pscustomobject]@{ Verdict = 'false-positive'; DecidedUtc = ''; PreviousVerdicts = @() }; ActionLog = @() }
        )

        $Metrics = Get-PSITSocMetrics -Cases $Cases

        $Metrics.ByWeek[0].Week | Should -Be '2026-S31'
        $Metrics.ByWeek[0].TruePositives | Should -Be 1
        $Metrics.ByWeek[1].Week | Should -Be '2026-S32'
        $Metrics.ByWeek[2].Week | Should -Be '2026-S36'
        $Metrics.ByWeek[2].FalsePositives | Should -Be 1
    }
}
