function Get-PSITSocAnalysts {
    <#
    .SYNOPSIS
        Lists the people a SOC dossier can be assigned to.
    .DESCRIPTION
        Two sources, in order of authority.

        The platform's own roster first: the allowedUsers table, which is what the CIPP Users page
        maintains - the list that decides who reaches which page of this portal. It is the right
        answer when it exists, because holding a role here is what makes someone assignable.

        It is not always filled. It is written by hand from CIPP Users, and automatically by
        Start-UserSyncTimer for deployments that map Entra groups to CIPP roles; a portal whose
        access is granted only through the static web app's own invitations has an empty table
        while people use it every day. That was this endpoint's first shape, and it answered an
        empty list with no error and no warning - a reassignment picker that said 'No options'
        with nothing anywhere saying why. So when the roster is empty, the partner tenant's own
        accounts are listed instead, and the answer says that is what happened and where to fix it.

        Display names and the fallback roster both come from Graph on the partner tenant, read the
        way Start-UserSyncTimer reads it - app-only, no auth check - because that is the call this
        repository already proves against that tenant.

        Every way of coming back without names is reported, with its counts: Graph refusing, Graph
        answering nothing, and two lists that exist without meeting. None of them empties the list:
        addresses are shown, because handing a dossier over is exactly the gesture an outage should
        not block.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param()

    $Warnings = [System.Collections.Generic.List[string]]::new()

    $Table = Get-CippTable -tablename 'allowedUsers'
    # Rows starting with '_' are the table's own bookkeeping, the same exclusion the platform's
    # user management applies.
    $Roster = @(Get-CIPPAzDataTableEntity @Table | Where-Object { $_.RowKey -and -not $_.RowKey.StartsWith('_') })

    $Directory = @()
    try {
        # One page covers a partner tenant's staff. Same call shape as Start-UserSyncTimer, which
        # is the function that fills the table read above.
        $GraphUsers = New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/users?`$select=userPrincipalName,displayName,accountEnabled,userType&`$top=999" -tenantid $env:TenantID -NoAuthCheck $true -AsApp $true
        # The helper unwraps the response's value collection, but a caller that ever got the
        # envelope instead would see every row fail the filter below and answer 'no names' without
        # a single error. Unwrap defensively rather than report an outage that did not happen.
        if ($null -ne $GraphUsers -and $null -eq $GraphUsers.userPrincipalName -and $null -ne $GraphUsers.value) {
            $GraphUsers = $GraphUsers.value
        }
        $Directory = @($GraphUsers | Where-Object {
                $_.userPrincipalName -and $_.accountEnabled -ne $false -and $_.userType -ne 'Guest'
            })
        if ($Directory.Count -eq 0) {
            $Warnings.Add('Display names unavailable: the partner tenant answered without a single account. Addresses are shown instead.')
        }
    } catch {
        $Warnings.Add("Display names unavailable: the partner tenant did not answer ($($_.Exception.Message)). Addresses are shown instead.")
    }

    $NamesByUpn = @{}
    foreach ($GraphUser in $Directory) {
        $NamesByUpn[$GraphUser.userPrincipalName.ToLowerInvariant()] = [string]$GraphUser.displayName
    }

    if ($Roster.Count -gt 0) {
        $Analysts = foreach ($User in $Roster) {
            $Upn = [string]$User.RowKey
            [PSCustomObject]@{
                userPrincipalName = $Upn
                displayName       = [string]($NamesByUpn[$Upn.ToLowerInvariant()] ?? '')
            }
        }
        $Analysts = @($Analysts)
        # Graph answered, and not one of its accounts is a portal user: the two lists exist and do
        # not meet. Saying which two counts failed to join is the difference between a fixable
        # report and 'the names do not show'.
        if ($NamesByUpn.Count -gt 0 -and @($Analysts | Where-Object { $_.displayName }).Count -eq 0) {
            $Warnings.Add("Display names unavailable: none of the $($Roster.Count) portal users matched any of the $($NamesByUpn.Count) accounts read from the partner tenant. Addresses are shown instead.")
        }
    } else {
        # No roster at all. Listing the tenant's accounts keeps reassignment working, and the
        # warning says plainly that this list is the directory rather than the portal's users.
        $Analysts = @($Directory | ForEach-Object {
                [PSCustomObject]@{
                    userPrincipalName = [string]$_.userPrincipalName
                    displayName       = [string]$_.displayName
                }
            })
        $Warnings.Add("The portal's user list is empty, so the $($Analysts.Count) accounts of the partner tenant are listed instead. Add the analysts under CIPP > Advanced > Authentication > CIPP Users to assign dossiers from the portal's own roster.")
    }

    [PSCustomObject]@{
        Analysts = @($Analysts | Sort-Object -Property @{ Expression = { if ($_.displayName) { $_.displayName } else { $_.userPrincipalName } } })
        Warnings = @($Warnings)
    }
}
