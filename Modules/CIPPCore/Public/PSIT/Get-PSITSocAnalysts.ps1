function Get-PSITSocAnalysts {
    <#
    .SYNOPSIS
        Lists the portal's own users as assignment candidates for a SOC case.
    .DESCRIPTION
        The people a case can be assigned to are the people who can sign in to this portal: the
        allowedUsers table, which is what the platform's own user management maintains. Their
        display names come from Graph on the partner tenant, where those accounts live.

        A Graph failure degrades to email-only entries with a named warning, never to an empty
        list: reassignment must keep working when Graph does not, because handing a case over is
        exactly the kind of gesture an outage should not block.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param()

    $Table = Get-CippTable -tablename 'allowedUsers'
    # Rows starting with '_' are the table's own bookkeeping, the same exclusion the platform's
    # user management applies.
    $Users = @(Get-CIPPAzDataTableEntity @Table | Where-Object { $_.RowKey -and -not $_.RowKey.StartsWith('_') })

    $Warnings = [System.Collections.Generic.List[string]]::new()
    $NamesByUpn = @{}
    if ($Users.Count -gt 0) {
        try {
            # One page covers the team: portal users are a handful of analysts, not a directory.
            $GraphUsers = New-GraphGetRequest -uri "https://graph.microsoft.com/beta/users?`$select=userPrincipalName,displayName&`$top=999" -tenantid $env:TenantID -NoAuthCheck $true
            # The helper unwraps the response's value collection, but a caller that ever gets the
            # envelope instead would see every row silently fail the userPrincipalName filter
            # below and answer 'no names' without a single error. Unwrap defensively rather than
            # report an outage that did not happen.
            if ($null -ne $GraphUsers -and $null -eq $GraphUsers.userPrincipalName -and $null -ne $GraphUsers.value) {
                $GraphUsers = $GraphUsers.value
            }
            foreach ($GraphUser in @($GraphUsers | Where-Object { $_.userPrincipalName })) {
                $NamesByUpn[$GraphUser.userPrincipalName.ToLowerInvariant()] = [string]$GraphUser.displayName
            }
            # Graph answering nothing is not the same as Graph refusing, and it used to be just as
            # silent: the queue showed addresses with no error and no warning, which is the state
            # that cost an afternoon of guessing. Both are now reported, with their counts.
            if ($NamesByUpn.Count -eq 0) {
                $Warnings.Add("Display names unavailable: the partner tenant answered without a single user. Emails are shown instead.")
            }
        } catch {
            $Warnings.Add("Display names unavailable: the partner tenant did not answer ($($_.Exception.Message)). Emails are shown instead.")
        }
    }

    $Analysts = foreach ($User in $Users) {
        $Upn = [string]$User.RowKey
        [PSCustomObject]@{
            userPrincipalName = $Upn
            displayName       = [string]($NamesByUpn[$Upn.ToLowerInvariant()] ?? '')
        }
    }

    # Graph answered, and not one of its users is a portal user: the two lists exist and do not
    # meet. Saying which two counts failed to join is the difference between a fixable report and
    # 'the names do not show'.
    $Resolved = @($Analysts | Where-Object { $_.displayName }).Count
    if ($Users.Count -gt 0 -and $NamesByUpn.Count -gt 0 -and $Resolved -eq 0) {
        $Warnings.Add("Display names unavailable: none of the $($Users.Count) portal users matched any of the $($NamesByUpn.Count) accounts read from the partner tenant. Emails are shown instead.")
    }

    [PSCustomObject]@{
        Analysts = @($Analysts | Sort-Object -Property @{ Expression = { if ($_.displayName) { $_.displayName } else { $_.userPrincipalName } } })
        Warnings = @($Warnings)
    }
}
