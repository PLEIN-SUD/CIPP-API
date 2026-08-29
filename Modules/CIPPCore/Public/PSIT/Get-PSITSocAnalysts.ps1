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
            foreach ($GraphUser in @($GraphUsers | Where-Object { $_.userPrincipalName })) {
                $NamesByUpn[$GraphUser.userPrincipalName.ToLowerInvariant()] = [string]$GraphUser.displayName
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

    [PSCustomObject]@{
        Analysts = @($Analysts | Sort-Object -Property @{ Expression = { if ($_.displayName) { $_.displayName } else { $_.userPrincipalName } } })
        Warnings = @($Warnings)
    }
}
