using namespace System.Net

Function Invoke-ListSpamfilter {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Exchange.SpamFilter.Read
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    Write-LogMessage -headers $Headers -API $APIName -message 'Accessed this API' -Sev 'Debug'
    $Tenantfilter = $Request.Query.tenantfilter

    try {
        # ----- Entrant -----
        $InboundPolicies = New-ExoRequest -tenantid $Tenantfilter -cmdlet 'Get-HostedContentFilterPolicy' | 
            Select-Object * -ExcludeProperty *odata*, *data.type*

        $InboundRules = New-ExoRequest -tenantid $Tenantfilter -cmdlet 'Get-HostedContentFilterRule' | 
            Select-Object * -ExcludeProperty *odata*, *data.type*

        $InboundCombined = $InboundPolicies | Select-Object *, 
            @{Name = 'RuleState'; Expression = { $name = $_.Name; ($InboundRules | Where-Object Name -eq $name).State }},
            @{Name = 'RulePriority'; Expression = { $name = $_.Name; ($InboundRules | Where-Object Name -eq $name).Priority }}

        # ----- Sortant -----
        $OutboundPolicies = New-ExoRequest -tenantid $Tenantfilter -cmdlet 'Get-HostedOutboundSpamFilterPolicy' | 
            Select-Object * -ExcludeProperty *odata*, *data.type*

        $OutboundRules = New-ExoRequest -tenantid $Tenantfilter -cmdlet 'Get-HostedOutboundSpamFilterRule' | 
            Select-Object * -ExcludeProperty *odata*, *data.type*

        $OutboundCombined = $OutboundPolicies | Select-Object *, 
            @{Name = 'RuleState'; Expression = { $name = $_.Name; ($OutboundRules | Where-Object Name -eq $name).State }},
            @{Name = 'RulePriority'; Expression = { $name = $_.Name; ($OutboundRules | Where-Object Name -eq $name).Priority }}

        # Combinaison des deux résultats
        $GraphRequest = [PSCustomObject]@{
            InboundSpamPolicies  = $InboundCombined
            OutboundSpamPolicies = $OutboundCombined
        }

        $StatusCode = [HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
        $StatusCode = [HttpStatusCode]::Forbidden
        $GraphRequest = $ErrorMessage
    }

    # Output bindings
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = $StatusCode
        Body       = @($GraphRequest)
    })
}
