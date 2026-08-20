function Test-PSITNonUserMailbox {
    <#
    .SYNOPSIS
        Tests whether a Graph user is one of the non-user mailboxes in the given index.

    .DESCRIPTION
        Companion to Get-PSITNonUserMailboxIndex. The index is keyed on object id, UPN and
        primary SMTP address because the cached mailbox and the Graph user do not always agree
        on which of those is populated, so every identifier the user carries is tried.

    .PARAMETER Index
        Index returned by Get-PSITNonUserMailboxIndex.

    .PARAMETER User
        A Graph user object (id / UserPrincipalName / mail).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.HashSet[string]]$Index,
        [Parameter(Mandatory = $true)]
        $User
    )

    foreach ($Key in @($User.id, $User.UserPrincipalName, $User.mail)) {
        if ($Key -and $Index.Contains([string]$Key)) { return $true }
    }

    return $false
}
