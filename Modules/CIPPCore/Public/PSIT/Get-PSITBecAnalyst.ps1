function Get-PSITBecAnalyst {
    <#
    .SYNOPSIS
        Resolves the signed-in analyst from the request headers.

    .DESCRIPTION
        A triage determination is only worth anything if it carries a name and a timestamp: the
        BEC report claims to be an audit trail, and "someone decided the Italian session was
        legitimate" is not an audit trail. The decoding mirrors Write-LogMessage, which is the
        existing authority in this codebase on turning Static Web Apps headers into a username.

        Falls back to 'unknown' rather than throwing: a determination recorded under an unknown
        analyst is still better evidence than no determination, and the caller has already been
        authorised by the RBAC layer at this point.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        $Headers
    )

    try {
        $Idp = [string]$Headers.'x-ms-client-principal-idp'
        if ($Idp -eq 'aad') {
            $ClientName = [string]$Headers.'x-ms-client-principal-name'
            if ($ClientName) { return "api-client:$ClientName" }
        }

        $Principal = [string]$Headers.'x-ms-client-principal'
        if ($Principal) {
            $Decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Principal)) | ConvertFrom-Json
            if ($Decoded.userDetails) { return [string]$Decoded.userDetails }
        }
    } catch {
        Write-Information "Could not resolve the calling analyst from the request headers: $($_.Exception.Message)"
    }

    return 'unknown'
}
