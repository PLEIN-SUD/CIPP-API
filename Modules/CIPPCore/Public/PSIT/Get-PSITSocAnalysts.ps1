function Get-PSITSocAnalysts {
    <#
    .SYNOPSIS
        Lists the people a SOC dossier can be assigned to.
    .DESCRIPTION
        Three sources, in order of authority.

        An Entra group when one is configured: the team that actually takes SOC work is often a
        group already, and naming it is more precise than either list below. Its id lives in
        configuration, never in this repository, because it is a production fact about one tenant
        and these repositories are public.

        The platform's own roster next: the allowedUsers table, which is what the CIPP Users page
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

        Those are Warnings: something is wrong and the analyst should see it. Which source the list
        came from is a Note instead - true, worth knowing once on the settings screen, and no
        business interrupting a triage screen every time it opens. The two are answered separately
        so each is read where it can be acted on.

        Both are written in French: they are shown to the analysts, and this section is theirs. The
        log lines stay in English, like every other log in this repository.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param()

    $Warnings = [System.Collections.Generic.List[string]]::new()
    $Notes = [System.Collections.Generic.List[string]]::new()

    # A configured group answers on its own: it names the team, which neither list below does.
    $Group = Get-PSITSocAnalystGroup
    if ($Group) {
        try {
            # transitiveMembers, like the platform's own user sync: an analyst in a nested group is
            # still an analyst. Same call shape, app-only, against the partner tenant.
            $Members = @(New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/groups/$($Group.GroupId)/transitiveMembers?`$select=id,userPrincipalName,displayName,accountEnabled,jobTitle&`$top=999" -tenantid $env:TenantID -NoAuthCheck $true -AsApp $true)
            $Analysts = @($Members |
                    Where-Object { $_.userPrincipalName -and $_.accountEnabled -ne $false } |
                    ForEach-Object {
                        [pscustomobject]@{
                            userPrincipalName = [string]$_.userPrincipalName
                            displayName       = [string]$_.displayName
                            jobTitle          = [string]$_.jobTitle
                        }
                    })
            if ($Analysts.Count -eq 0) {
                $Warnings.Add("Le groupe « $($Group.GroupName) » ne contient aucun utilisateur actif : aucun analyste ne peut être proposé. Vérifiez ses membres, ou retirez le groupe pour revenir aux utilisateurs du portail.")
            }
            return [pscustomobject]@{
                Analysts = @($Analysts | Sort-Object -Property @{ Expression = { if ($_.displayName) { $_.displayName } else { $_.userPrincipalName } } })
                Warnings = @($Warnings)
                Notes    = @("Analystes pris dans le groupe « $($Group.GroupName) ».")
            }
        } catch {
            # The configured group is the stated intent: falling back to a wider list without
            # saying so would quietly offer people the group deliberately excludes.
            $Warnings.Add("Le groupe d'analystes « $($Group.GroupName) » n'a pas pu être lu ($($_.Exception.Message)). Aucun analyste n'est proposé, plutôt qu'une liste que ce groupe était censé restreindre.")
            return [pscustomobject]@{ Analysts = @(); Warnings = @($Warnings); Notes = @() }
        }
    }

    $Table = Get-CippTable -tablename 'allowedUsers'
    # Rows starting with '_' are the table's own bookkeeping, the same exclusion the platform's
    # user management applies.
    $Roster = @(Get-CIPPAzDataTableEntity @Table | Where-Object { $_.RowKey -and -not $_.RowKey.StartsWith('_') })

    $Directory = @()
    try {
        # One page covers a partner tenant's staff. Same call shape as Start-UserSyncTimer, which
        # is the function that fills the table read above.
        $GraphUsers = New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/users?`$select=userPrincipalName,displayName,accountEnabled,userType,jobTitle&`$top=999" -tenantid $env:TenantID -NoAuthCheck $true -AsApp $true
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
            $Warnings.Add('Noms indisponibles : le tenant partenaire a répondu sans aucun compte. Les adresses sont affichées à la place.')
        }
    } catch {
        $Warnings.Add("Noms indisponibles : le tenant partenaire n'a pas répondu ($($_.Exception.Message)). Les adresses sont affichées à la place.")
    }

    $NamesByUpn = @{}
    $TitlesByUpn = @{}
    foreach ($GraphUser in $Directory) {
        $Key = $GraphUser.userPrincipalName.ToLowerInvariant()
        $NamesByUpn[$Key] = [string]$GraphUser.displayName
        $TitlesByUpn[$Key] = [string]$GraphUser.jobTitle
    }

    if ($Roster.Count -gt 0) {
        $Analysts = foreach ($User in $Roster) {
            $Upn = [string]$User.RowKey
            [PSCustomObject]@{
                userPrincipalName = $Upn
                displayName       = [string]($NamesByUpn[$Upn.ToLowerInvariant()] ?? '')
                jobTitle          = [string]($TitlesByUpn[$Upn.ToLowerInvariant()] ?? '')
            }
        }
        $Analysts = @($Analysts)
        # Graph answered, and not one of its accounts is a portal user: the two lists exist and do
        # not meet. Saying which two counts failed to join is the difference between a fixable
        # report and 'the names do not show'.
        if ($NamesByUpn.Count -gt 0 -and @($Analysts | Where-Object { $_.displayName }).Count -eq 0) {
            $Warnings.Add("Noms indisponibles : aucun des $($Roster.Count) utilisateurs du portail ne correspond aux $($NamesByUpn.Count) comptes lus sur le tenant partenaire. Les adresses sont affichées à la place.")
        }
    } else {
        # No roster at all. Listing the tenant's accounts keeps reassignment working, and the
        # warning says plainly that this list is the directory rather than the portal's users.
        $Analysts = @($Directory | ForEach-Object {
                [PSCustomObject]@{
                    userPrincipalName = [string]$_.userPrincipalName
                    displayName       = [string]$_.displayName
                    jobTitle          = [string]$_.jobTitle
                }
            })
        # A note, not a warning: nothing is broken, the list simply comes from the directory. It
        # belongs on the settings screen, where a group can be named, not above a triage queue.
        $Notes.Add("La liste des utilisateurs du portail est vide : les $($Analysts.Count) comptes du tenant partenaire sont proposés. Indiquez un groupe d'analystes ci-dessous pour n'en proposer qu'une équipe.")
    }

    [PSCustomObject]@{
        Analysts = @($Analysts | Sort-Object -Property @{ Expression = { if ($_.displayName) { $_.displayName } else { $_.userPrincipalName } } })
        Warnings = @($Warnings)
        Notes    = @($Notes)
    }
}
