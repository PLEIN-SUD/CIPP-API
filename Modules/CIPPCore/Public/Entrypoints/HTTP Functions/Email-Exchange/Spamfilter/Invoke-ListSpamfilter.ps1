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

        $InboundCombined = $InboundPolicies | ForEach-Object {
            $rule = $InboundRules | Where-Object Name -eq $_.Name
            $_ | Select-Object *, 
                @{Name='RuleState'; Expression={$rule.State}},
                @{Name='RulePriority'; Expression={$rule.Priority}},
                @{Name='Direction'; Expression={'Inbound'}}
        }

        # ----- Sortant -----
        $OutboundPolicies = New-ExoRequest -tenantid $Tenantfilter -cmdlet 'Get-HostedOutboundSpamFilterPolicy' | 
            Select-Object * -ExcludeProperty *odata*, *data.type*

        $OutboundRules = New-ExoRequest -tenantid $Tenantfilter -cmdlet 'Get-HostedOutboundSpamFilterRule' | 
            Select-Object * -ExcludeProperty *odata*, *data.type*

        $OutboundCombined = $OutboundPolicies | ForEach-Object {
            $rule = $OutboundRules | Where-Object Name -eq $_.Name
            $_ | Select-Object *, 
                @{Name='RuleState'; Expression={$rule.State}},
                @{Name='RulePriority'; Expression={$rule.Priority}},
                @{Name='Direction'; Expression={'Outbound'}}
        }

        # Fusion des deux
        $GraphRequest = $InboundCombined + $OutboundCombined
        $StatusCode = [HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
        $StatusCode = [HttpStatusCode]::Forbidden
        $GraphRequest = $ErrorMessage
    }

    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = $StatusCode
        Body       = @($GraphRequest)
    })
}
