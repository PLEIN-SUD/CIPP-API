function Set-PSITMdeIsolation {
    <#
    .SYNOPSIS
        Isolates a machine from the network through Defender for Endpoint, or releases it.

    .DESCRIPTION
        The containment gesture for a machine-side case: the endpoint keeps running and stays
        reachable by Defender, but nothing else gets in or out. It is the machine equivalent of
        revoking sessions on an identity, and the SOC dashboard offers it on confirmation only.

        Built on the exact path upstream already uses to act on machines
        (Invoke-CIPPMDEOffboard): the Defender for Endpoint API, reached through
        New-Graph*Request with the securitycenter scope, authorised by the delegated GDAP token.
        No SAM manifest change is attempted here on purpose - adding a permission GUID that
        cannot be verified from this repository, to a manifest deployed on every managed tenant,
        would be a worse bug than a missing button. If the lab returns 403 where offboard
        succeeds, that is the moment to revisit the manifest, with the GUID read from the tenant's
        own WindowsDefenderATP service principal.

        Isolation is 'Full' rather than 'Selective': selective isolation still allows Outlook,
        Teams and Skype traffic, which is precisely what a compromised mailbox uses. An analyst
        who wants the softer variant does it from the Defender portal and records it on the case.

    .PARAMETER AzureADDeviceId
        Entra device id. MDE stores it as aadDeviceId on the machine record, which is how a
        managed device is matched to its Defender machine.

    .PARAMETER Release
        Releases the machine from isolation instead of isolating it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AzureADDeviceId,

        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,

        [Parameter(Mandatory = $true)]
        [string]$Analyst,

        [string]$Comment,

        [switch]$Release
    )

    if ($AzureADDeviceId -eq '00000000-0000-0000-0000-000000000000' -or [string]::IsNullOrWhiteSpace($AzureADDeviceId)) {
        throw 'Device has no Entra device id, so it cannot be matched to a Defender for Endpoint machine record.'
    }

    $Scope = 'https://api.securitycenter.microsoft.com/.default'
    $Machines = @(New-GraphGetRequest -tenantid $TenantFilter -uri "https://api.securitycenter.microsoft.com/api/machines?`$filter=aadDeviceId eq $AzureADDeviceId" -scope $Scope)

    $Onboarded = @($Machines | Where-Object { $_.onboardingStatus -eq 'Onboarded' })
    if ($Onboarded.Count -eq 0) {
        if ($Machines.Count -gt 0) {
            throw "Found $($Machines.Count) Defender for Endpoint machine record(s) for this device, but none are currently onboarded."
        }
        throw 'No Defender for Endpoint machine record found for this device.'
    }

    $Action = if ($Release) { 'unisolate' } else { 'isolate' }
    $Reason = if ([string]::IsNullOrWhiteSpace($Comment)) { "SOC triage, by $Analyst" } else { $Comment }
    $Body = if ($Release) {
        @{ Comment = $Reason } | ConvertTo-Json -Compress
    } else {
        @{ Comment = $Reason; IsolationType = 'Full' } | ConvertTo-Json -Compress
    }

    $Results = [System.Collections.Generic.List[object]]::new()
    foreach ($Machine in $Onboarded) {
        $Name = $Machine.computerDnsName ?? $Machine.id
        try {
            $null = New-GraphPOSTRequest -uri "https://api.securitycenter.microsoft.com/api/machines/$($Machine.id)/$Action" -tenantid $TenantFilter -body $Body -scope $Scope
            $Results.Add([pscustomobject]@{
                    resultText = "Queued $Action for $Name"
                    state      = 'success'
                })
        } catch {
            # One machine record failing must not hide the others: a device can carry several.
            $Results.Add([pscustomobject]@{
                    resultText = "Failed to $Action ${Name}: $($_.Exception.Message)"
                    state      = 'error'
                })
        }
    }

    Write-LogMessage -API 'PSITExecMdeIsolation' -tenant $TenantFilter -message "Defender for Endpoint $Action requested on $($Onboarded.Count) machine record(s) by $Analyst" -sev Info

    return [pscustomobject]@{
        Action   = $Action
        Machines = @($Onboarded | ForEach-Object { $_.computerDnsName } | Where-Object { $_ })
        Results  = @($Results)
    }
}
