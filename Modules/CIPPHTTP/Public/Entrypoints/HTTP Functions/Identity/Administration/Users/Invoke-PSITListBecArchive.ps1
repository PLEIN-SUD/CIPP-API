Function Invoke-PSITListBecArchive {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Identity.User.Read
    .DESCRIPTION
        Reads back the evidence archived when a BEC case was closed. Without a reference, lists the
        archived collections of a mailbox - reference, when it was collected, when it was archived
        and by whom - which is a few hundred bytes per case. With a reference, returns that
        collection whole, which is hundreds of kilobytes: hence the two modes, so a page load never
        pulls the payload it does not need.

        The upstream cache keeps one collection per mailbox and the next run overwrites it, so this
        is the only trace left of what a closed case was investigated from.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $TenantFilter = $Request.Query.tenantFilter ?? $Request.Body.tenantFilter
    $UserId = $Request.Query.userId ?? $Request.Body.userId
    $Reference = $Request.Query.reference ?? $Request.Body.reference

    if ([string]::IsNullOrWhiteSpace($TenantFilter) -or [string]::IsNullOrWhiteSpace($UserId)) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = 'tenantFilter and userId are both required.' }
            })
    }

    try {
        $Table = Get-CippTable -tablename 'PSITBecCollections'

        if ($Reference) {
            $RowKey = '{0}_{1}' -f $UserId, $Reference
            $Row = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$TenantFilter' and RowKey eq '$RowKey'"
            if (-not $Row.Collection) {
                return ([HttpResponseContext]@{
                        StatusCode = [HttpStatusCode]::NotFound
                        Body       = @{ Results = "No archived collection for $Reference." }
                    })
            }
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::OK
                    Body       = @{
                        Reference    = [string]$Row.Reference
                        CollectedUtc = [string]$Row.CollectedUtc
                        ArchivedUtc  = [string]$Row.ArchivedUtc
                        ArchivedBy   = [string]$Row.ArchivedBy
                        # The collection as it was stored: a JSON string, handed back verbatim so
                        # what the analyst downloads is byte-for-byte what the reports were built
                        # from.
                        Collection   = [string]$Row.Collection
                    }
                })
        }

        # Listing mode: the payload column is deliberately not selected.
        $Rows = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$TenantFilter' and RowKey ge '$($UserId)_' and RowKey le '$($UserId)_~'" -Property @('RowKey', 'Reference', 'CollectedUtc', 'ArchivedUtc', 'ArchivedBy')
        $List = foreach ($Row in @($Rows | Where-Object { $_.Reference })) {
            [pscustomobject]@{
                Reference    = [string]$Row.Reference
                CollectedUtc = [string]$Row.CollectedUtc
                ArchivedUtc  = [string]$Row.ArchivedUtc
                ArchivedBy   = [string]$Row.ArchivedBy
            }
        }

        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = @{ Archives = @(@($List) | Sort-Object -Property ArchivedUtc -Descending) }
            })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API 'PSITListBecArchive' -tenant $TenantFilter -message "Failed to read the archived collections for $($UserId): $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::InternalServerError
                Body       = @{ Results = "Could not read the archive: $($ErrorMessage.NormalizedError)" }
            })
    }
}
