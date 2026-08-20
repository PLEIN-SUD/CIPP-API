function Close-PSITBecIncident {
    <#
    .SYNOPSIS
        Closes the open case on a mailbox and frees the slot for the next one.

    .DESCRIPTION
        Both PSIT tables are keyed on the mailbox, one row per user, which is fine until the same
        mailbox is compromised a second time. Then everything from the first case leaks into the
        second: its reference, its detection date, its data categories, its third parties, its
        acknowledgement - and, worse, its determinations. Signal ids are derived from stable
        discriminators (source address, rule name), so an attacker returning from the same address
        inherits the answer given in August, and a signal qualified "expected" then is filed as
        noise now, silently.

        Closing archives both rows under RowKey "<UserId>_<Reference>" and removes the live ones.
        Nothing is lost, nothing is inherited: the next save opens a case with a fresh reference and
        empty fields, and the determinations of the closed case can no longer silence anything.

        A closed case stays readable - Get-PSITBecIncident lists them - because a repeat compromise
        of the same mailbox is itself a finding, for the analyst and for the client's DPO.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,

        [Parameter(Mandatory = $true)]
        [string]$UserId,

        [Parameter(Mandatory = $true)]
        [string]$Analyst,

        # Free text: why the case is being closed. Kept on the archived row.
        [string]$ClosureNote
    )

    $IncidentTable = Get-CippTable -tablename 'PSITBecIncidents'
    $Incident = Get-CIPPAzDataTableEntity @IncidentTable -Filter "PartitionKey eq '$TenantFilter' and RowKey eq '$UserId'"

    if (-not $Incident.Reference) {
        return [pscustomobject]@{
            Closed = $false
            Reason = 'No open case file on this mailbox, so there is nothing to close.'
        }
    }

    $Now = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $Reference = [string]$Incident.Reference
    $ArchiveKey = '{0}_{1}' -f $UserId, $Reference

    # Copy every stored property rather than re-listing them: a field added to the case file later
    # must not silently stop being archived.
    $ArchivedIncident = @{}
    foreach ($Property in $Incident.PSObject.Properties) {
        if ($Property.Name -in @('PartitionKey', 'RowKey', 'Timestamp', 'ETag', 'odata.etag')) { continue }
        if ($null -eq $Property.Value) { continue }
        $ArchivedIncident[$Property.Name] = $Property.Value
    }
    $ArchivedIncident['PartitionKey'] = $TenantFilter
    $ArchivedIncident['RowKey'] = $ArchiveKey
    $ArchivedIncident['Archived'] = $true
    $ArchivedIncident['ClosedUtc'] = $Now
    $ArchivedIncident['ClosedBy'] = $Analyst
    if ($ClosureNote) { $ArchivedIncident['ClosureNote'] = $ClosureNote }
    $ArchivedIncident['UserId'] = $UserId

    $null = Add-CIPPAzDataTableEntity @IncidentTable -Entity $ArchivedIncident -Force

    # The determinations follow the case they were made for. Archived under the same key, so a
    # closed case can be re-read whole.
    $TriageTable = Get-CippTable -tablename 'PSITBecTriage'
    $Triage = Get-CIPPAzDataTableEntity @TriageTable -Filter "PartitionKey eq '$TenantFilter' and RowKey eq '$UserId'"
    $ArchivedDeterminations = 0
    if ($Triage.Determinations) {
        $ArchivedTriage = @{
            PartitionKey   = $TenantFilter
            RowKey         = $ArchiveKey
            UserId         = $UserId
            Reference      = $Reference
            Determinations = [string]$Triage.Determinations
            Archived       = $true
            ClosedUtc      = $Now
            ClosedBy       = $Analyst
        }
        if ($Triage.UserPrincipalName) { $ArchivedTriage['UserPrincipalName'] = [string]$Triage.UserPrincipalName }
        $null = Add-CIPPAzDataTableEntity @TriageTable -Entity $ArchivedTriage -Force
        try {
            $ArchivedDeterminations = @([string]$Triage.Determinations | ConvertFrom-Json -ErrorAction Stop).Count
        } catch {
            $ArchivedDeterminations = 0
        }
    }

    # Only now: the live rows go, after both archives are written. A crash between the two leaves a
    # duplicate to clean up, which is recoverable - the reverse order loses the case.
    Remove-AzDataTableEntity @IncidentTable -Entity ([pscustomobject]@{ PartitionKey = $TenantFilter; RowKey = $UserId }) -Force
    if ($Triage.Determinations) {
        Remove-AzDataTableEntity @TriageTable -Entity ([pscustomobject]@{ PartitionKey = $TenantFilter; RowKey = $UserId }) -Force
    }

    Write-LogMessage -API 'PSITBecIncident' -tenant $TenantFilter -message "Incident $Reference closed and archived by $Analyst ($ArchivedDeterminations determination(s) archived)" -sev Info

    return [pscustomobject]@{
        Closed                 = $true
        Reference              = $Reference
        ArchiveKey             = $ArchiveKey
        ClosedUtc              = $Now
        ClosedBy               = $Analyst
        ArchivedDeterminations = $ArchivedDeterminations
    }
}
