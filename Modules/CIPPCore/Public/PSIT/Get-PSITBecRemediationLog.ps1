function Get-PSITBecRemediationLog {
    <#
    .SYNOPSIS
        Reconstructs what was actually done to a compromised mailbox, from CIPP's own log.

    .DESCRIPTION
        The containment section of an incident report is the one an insurer, a DPO or a court will
        read closely, so it must not be a set of checkboxes an analyst ticked from memory. CIPP
        already records every remediation it performs - the BEC "Remediate User" button and the
        individual actions alike - through Write-LogMessage, with the operator's name and a
        timestamp. This reads that trail back.

        CippLogs is partitioned by local date (yyyyMMdd in CIPP_TIMEZONE, UTC by default), so the
        window is walked one partition at a time rather than scanned whole.

        Matching is deliberately conservative: an entry counts only when it comes from a known
        remediation endpoint AND mentions the mailbox. Actions taken outside CIPP - a password
        reset in the Entra portal, a bank called, a supplier warned - cannot appear here, which is
        exactly why the report also carries analyst-entered actions and labels the two differently.

    .PARAMETER SinceUtc
        Start of the window. Capped at 90 days back, beyond which CippLogs retention makes the
        answer meaningless anyway.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,

        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName,

        [datetime]$SinceUtc = ([datetime]::UtcNow.AddDays(-30)),

        [string]$UserId
    )

    # Endpoints whose log entries are remediation of a user account. The API field carries the
    # endpoint name, so this is an exact match rather than a guess at message wording.
    $RemediationApis = @(
        'ExecBECRemediate', 'ExecResetPass', 'ExecDisableUser', 'ExecRevokeSessions',
        'ExecResetMFA', 'ExecRemoveAdminRole', 'ExecSetCloudManaged', 'ExecSetDefaultMFAMethod',
        'ExecMailboxRule', 'ExecEditMailboxPermissions', 'ExecDisableEmailForward',
        'ExecRemoveOneDriveSharing', 'ExecOneDriveSharing', 'RemoveMailboxRule', 'ExecRevokeConsent'
    )

    # What the log message means, in the vocabulary the report uses. Ordered: the first pattern
    # that matches wins, so specific patterns come before generic ones.
    $ActionPatterns = @(
        @{ Pattern = '(?i)reset.*password|password.*reset'; Action = 'PasswordReset' }
        @{ Pattern = '(?i)disabled? (the )?account|sign[- ]?in.*(blocked|disabled)|accountEnabled'; Action = 'SignInBlocked' }
        @{ Pattern = '(?i)revoke.*session|session.*revoked'; Action = 'SessionsRevoked' }
        @{ Pattern = '(?i)mfa|authentication method|strong authentication'; Action = 'MfaMethodsRemoved' }
        # Broad on purpose: the endpoint logs "Successfully disabled rule: X", "Could not disable
        # rule 'X'", "Retrieved N total rules", "Skipping delegate rule". Matching only the past
        # tense filed the failures as 'Other', which is exactly the entry that must not be lost.
        @{ Pattern = '(?i)inbox rule|mailbox rule|\brules?\b'; Action = 'InboxRulesDisabled' }
        @{ Pattern = '(?i)onedrive|sharing link|sharing'; Action = 'SharingDisabled' }
        @{ Pattern = '(?i)forward'; Action = 'ForwardingRemoved' }
        @{ Pattern = '(?i)consent|service principal|application'; Action = 'ConsentRevoked' }
        @{ Pattern = '(?i)admin role|directory role'; Action = 'AdminRoleRemoved' }
    )

    $Cap = [datetime]::UtcNow.AddDays(-90)
    if ($SinceUtc -lt $Cap) { $SinceUtc = $Cap }

    $Table = Get-CippTable -tablename 'CippLogs'
    $Entries = [System.Collections.Generic.List[object]]::new()
    $Needles = @($UserPrincipalName, $UserId) | Where-Object { $_ }

    $Day = $SinceUtc.Date
    $Today = [datetime]::UtcNow.Date
    while ($Day -le $Today) {
        $PartitionKey = $Day.ToString('yyyyMMdd')
        try {
            $Rows = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$PartitionKey' and Tenant eq '$TenantFilter'"
        } catch {
            Write-Information "Could not read CippLogs partition $PartitionKey : $($_.Exception.Message)"
            $Rows = @()
        }

        foreach ($Row in @($Rows)) {
            if ([string]$Row.API -notin $RemediationApis) { continue }

            $Message = [string]$Row.Message
            $Matched = $false
            foreach ($Needle in $Needles) {
                if ($Message -like "*$Needle*") { $Matched = $true; break }
            }
            if (-not $Matched) { continue }

            $Action = 'Other'
            foreach ($Candidate in $ActionPatterns) {
                if ($Message -match $Candidate.Pattern) { $Action = $Candidate.Action; break }
            }

            $Timestamp = $null
            if ($Row.Timestamp) {
                try { $Timestamp = ([datetimeoffset]$Row.Timestamp).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ') } catch {}
            }

            $Entries.Add([pscustomobject]@{
                    TimestampUtc = $Timestamp
                    Action       = $Action
                    Api          = [string]$Row.API
                    Message      = $Message
                    Operator     = [string]$Row.Username
                    Severity     = [string]$Row.Severity
                    Source       = 'CIPP'
                })
        }

        $Day = $Day.AddDays(1)
    }

    $Sorted = @($Entries | Sort-Object -Property TimestampUtc)

    return [pscustomobject]@{
        TenantFilter      = $TenantFilter
        UserPrincipalName = $UserPrincipalName
        WindowStartUtc    = $SinceUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
        Entries           = $Sorted
        # One row per canonical action, so the report can state done/not-done without the reader
        # having to parse a log.
        ActionsPerformed  = @($Sorted | Group-Object -Property Action | ForEach-Object {
                $First = $_.Group | Where-Object { $_.TimestampUtc } | Select-Object -First 1
                [pscustomobject]@{
                    Action       = $_.Name
                    Count        = $_.Count
                    FirstUtc     = $First.TimestampUtc
                    Operator     = $First.Operator
                    HasFailure   = @($_.Group | Where-Object { $_.Severity -eq 'Error' }).Count -gt 0
                }
            })
    }
}
