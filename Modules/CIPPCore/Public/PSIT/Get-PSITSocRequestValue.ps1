function Get-PSITSocRequestValue {
    <#
    .SYNOPSIS
        Reads a request field that may arrive as a value or as an autocomplete selection.

    .DESCRIPTION
        The frontend's autoComplete control submits the whole option, {label, value}, not the
        value: a severity picked from a list arrives as @{value=P3; label=P3}. Upstream knows the
        trap and unwraps it by hand wherever it applies (Invoke-ExecSetSecurityIncident reads
        $Request.Body.Severity.value with a comment saying why).

        Doing it by hand is how it gets forgotten, and forgetting it fails in two different ways,
        one of them silent: a validated parameter throws (the analyst sees an error), while a
        field parsed loosely just fails to match and is dropped - a case adopted successfully but
        with no type, hence no investigation guide. This function is the one place that unwraps,
        so a new field cannot miss it.

        A plain value passes through untouched, which is what the webhook and any script send.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) { return $null }
    # A string is the common case and can carry a 'value' property lookup safely, so test it
    # first rather than relying on the property being absent.
    if ($Value -is [string] -or $Value -is [int] -or $Value -is [bool] -or $Value -is [long]) {
        return $Value
    }
    if ($Value -is [array]) {
        # A multi-select autocomplete: unwrap each entry, keep it a list.
        return @($Value | ForEach-Object { Get-PSITSocRequestValue -Value $_ })
    }
    if ($null -ne $Value.value) { return $Value.value }

    return $Value
}
