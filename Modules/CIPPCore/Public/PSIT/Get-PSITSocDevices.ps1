function Get-PSITSocDevices {
    <#
    .SYNOPSIS
        Every machine the tenant's two managers know, in one list saying who manages what.

    .DESCRIPTION
        Intune enrolls, Defender for Endpoint onboards, and neither list contains the other: a
        server onboarded by script lives in Defender only, a phone lives in Intune only. The
        device picker used to read Intune alone, which made MDE-only machines unselectable - and
        therefore uninvestigable - from this portal.

        Both worlds are read and joined on the Entra device id, the one identifier they share.
        Each row says who manages the machine, because that decides what works on it: Intune
        readings need Intune, isolation needs Defender, and an analyst should learn that from a
        column rather than from a failed action.

        One side failing does not empty the list, but it never fails silently either: a list
        quietly missing the Defender side would hide MDE-only machines exactly the way the old
        picker did, so the metadata names the side that could not be read.

    .PARAMETER IntuneDevices
        Injected rows for tests. Fetched when omitted, likewise MdeMachines.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,

        [AllowNull()]
        $IntuneDevices,

        [AllowNull()]
        $MdeMachines
    )

    $Warnings = [System.Collections.Generic.List[string]]::new()

    if ($null -eq $IntuneDevices) {
        try {
            $IntuneDevices = @(New-GraphGetRequest -tenantid $TenantFilter -uri 'https://graph.microsoft.com/beta/deviceManagement/managedDevices?$select=id,deviceName,azureADDeviceId,userPrincipalName,operatingSystem,lastSyncDateTime&$top=999')
        } catch {
            $IntuneDevices = $null
            $Warnings.Add("Intune unreadable: $($_.Exception.Message)")
        }
    }
    if ($null -eq $MdeMachines) {
        try {
            $MdeMachines = @(New-GraphGetRequest -tenantid $TenantFilter -uri 'https://api.securitycenter.microsoft.com/api/machines' -scope 'https://api.securitycenter.microsoft.com/.default')
        } catch {
            $MdeMachines = $null
            $Warnings.Add("Defender for Endpoint unreadable: $($_.Exception.Message)")
        }
    }
    if ($null -eq $IntuneDevices -and $null -eq $MdeMachines) {
        throw "Neither Intune nor Defender for Endpoint could be read for $TenantFilter. $($Warnings -join ' / ')"
    }

    $Empty = '00000000-0000-0000-0000-000000000000'
    $Rows = @{}

    foreach ($Device in @($IntuneDevices | Where-Object { $_ })) {
        $Key = [string]$Device.azureADDeviceId
        if ([string]::IsNullOrWhiteSpace($Key) -or $Key -eq $Empty) { $Key = "intune:$($Device.id)" }
        $Rows[$Key.ToLowerInvariant()] = [pscustomobject]@{
            DeviceName       = [string]$Device.deviceName
            ManagedBy        = 'Intune'
            IntuneId         = [string]$Device.id
            MdeId            = ''
            AzureADDeviceId  = [string]$Device.azureADDeviceId
            UserPrincipalName = [string]$Device.userPrincipalName
            OperatingSystem  = [string]$Device.operatingSystem
            LastSeen         = [string]$Device.lastSyncDateTime
            OnboardingStatus = ''
        }
    }

    foreach ($Machine in @($MdeMachines | Where-Object { $_ })) {
        $Aad = [string]$Machine.aadDeviceId
        $Key = if ([string]::IsNullOrWhiteSpace($Aad) -or $Aad -eq $Empty) { "mde:$($Machine.id)" } else { $Aad.ToLowerInvariant() }
        $Existing = $Rows[$Key]
        if ($Existing) {
            $Existing.ManagedBy = 'Intune + MDE'
            $Existing.MdeId = [string]$Machine.id
            $Existing.OnboardingStatus = [string]$Machine.onboardingStatus
            # The freshest sighting of the two: a machine can sync Intune daily and Defender hourly.
            if ([string]$Machine.lastSeen -gt $Existing.LastSeen) { $Existing.LastSeen = [string]$Machine.lastSeen }
        } else {
            $Rows[$Key] = [pscustomobject]@{
                DeviceName       = [string]$Machine.computerDnsName
                ManagedBy        = 'MDE'
                IntuneId         = ''
                MdeId            = [string]$Machine.id
                AzureADDeviceId  = if ($Aad -eq $Empty) { '' } else { $Aad }
                UserPrincipalName = ''
                OperatingSystem  = [string]$Machine.osPlatform
                LastSeen         = [string]$Machine.lastSeen
                OnboardingStatus = [string]$Machine.onboardingStatus
            }
        }
    }

    return [PSCustomObject]@{
        Results  = @($Rows.Values | Sort-Object -Property DeviceName)
        Metadata = [PSCustomObject]@{
            IntuneRead = $null -ne $IntuneDevices
            MdeRead    = $null -ne $MdeMachines
            Warnings   = @($Warnings)
        }
    }
}
