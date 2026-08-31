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

        The collection itself is archived too, into its own table. Upstream keeps one cachebec row
        per user, so the next run overwrites it: without this, closing a case left the reports as
        the only surviving trace of the evidence they were built from. It goes in a separate table
        rather than on the case row because the case row is read on every page load and the
        collection payload is hundreds of kilobytes.
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

    # The containment attestation is FROZEN here. It is read from CippLogs, whose retention is
    # 90 days: a case reopened for an insurer at J+120 would otherwise show 'nothing attested'
    # about gestures that were real. Closure is the archival moment, so this is where the trail
    # stops depending on its source. A failed read logs and archives without it - closing a case
    # must not be hostage to a log partition.
    try {
        $Upn = [string]$Incident.UserPrincipalName
        if ($Upn) {
            $Since = if ($Incident.DetectedUtc) { ([datetime]$Incident.DetectedUtc).AddDays(-2) } else { [datetime]::UtcNow.AddDays(-30) }
            $Trail = Get-PSITBecRemediationLog -TenantFilter $TenantFilter -UserPrincipalName $Upn -UserId $UserId -SinceUtc $Since
            $ArchivedIncident['ContainmentAttestation'] = [string]([pscustomobject]@{
                    FrozenUtc        = $Now
                    WindowStartUtc   = $Trail.WindowStartUtc
                    ActionsPerformed = @($Trail.ActionsPerformed)
                    Entries          = @($Trail.Entries | Select-Object -First 100)
                } | ConvertTo-Json -Depth 6 -Compress)
        }
    } catch {
        Write-LogMessage -API 'PSITBecIncident' -tenant $TenantFilter -message "Containment attestation could not be frozen on closure of $($Reference): $($_.Exception.Message)" -sev Warn
    }
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

    # The collection that the case was investigated from. Upstream overwrites it on the next run,
    # so this is the only chance to keep it.
    $CollectionArchived = $false
    try {
        $CacheTable = Get-CippTable -tablename 'cachebec'
        $Cached = Get-CIPPAzDataTableEntity @CacheTable -Filter "PartitionKey eq 'bec' and RowKey eq '$UserId'"
        if ($Cached.Results) {
            $CollectionTable = Get-CippTable -tablename 'PSITBecCollections'
            $CollectedUtc = ''
            try {
                $Parsed = [string]$Cached.Results | ConvertFrom-Json -ErrorAction Stop
                if ($Parsed.ExtractedAt) { $CollectedUtc = ([datetime]$Parsed.ExtractedAt).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
            } catch {
                $CollectedUtc = ''
            }
            $null = Add-CIPPAzDataTableEntity @CollectionTable -Entity @{
                PartitionKey = $TenantFilter
                RowKey       = $ArchiveKey
                UserId       = $UserId
                Reference    = $Reference
                CollectedUtc = $CollectedUtc
                ArchivedUtc  = $Now
                ArchivedBy   = $Analyst
                Collection   = [string]$Cached.Results
            } -Force
            $CollectionArchived = $true
        }
    } catch {
        # An archive that fails must not block the closure: the case file matters more than the
        # evidence copy, and the failure is logged rather than swallowed.
        Write-LogMessage -API 'PSITBecIncident' -tenant $TenantFilter -message "Incident $Reference closed, but the collection could not be archived: $($_.Exception.Message)" -sev Warn
    }

    # Only now: the live rows go, after both archives are written. A crash between the two leaves a
    # duplicate to clean up, which is recoverable - the reverse order loses the case.
    Remove-AzDataTableEntity @IncidentTable -Entity ([pscustomobject]@{ PartitionKey = $TenantFilter; RowKey = $UserId }) -Force
    if ($Triage.Determinations) {
        Remove-AzDataTableEntity @TriageTable -Entity ([pscustomobject]@{ PartitionKey = $TenantFilter; RowKey = $UserId }) -Force
    }

    Write-LogMessage -API 'PSITBecIncident' -tenant $TenantFilter -message "Incident $Reference closed and archived by $Analyst ($ArchivedDeterminations determination(s), collection archived: $CollectionArchived)" -sev Info

    return [pscustomobject]@{
        Closed                 = $true
        Reference              = $Reference
        ArchiveKey             = $ArchiveKey
        ClosedUtc              = $Now
        ClosedBy               = $Analyst
        ArchivedDeterminations = $ArchivedDeterminations
        CollectionArchived     = $CollectionArchived
    }
}
