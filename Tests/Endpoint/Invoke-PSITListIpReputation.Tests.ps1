# Pester tests for the IP reputation endpoints.
#
# What is pinned here: the list endpoint parses both input shapes and hands the work to the core
# function, and the key endpoint never echoes the key - a settings screen learns configured or
# not, by whom and when, nothing more.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $ListPath = Get-ChildItem -Path (Join-Path $RepoRoot 'Modules') -Recurse -Filter 'Invoke-PSITListIpReputation.ps1' -File |
        Select-Object -First 1 -ExpandProperty FullName
    $KeyPath = Get-ChildItem -Path (Join-Path $RepoRoot 'Modules') -Recurse -Filter 'Invoke-PSITExecIpReputationKey.ps1' -File |
        Select-Object -First 1 -ExpandProperty FullName
    if (-not $ListPath -or -not $KeyPath) { throw 'Could not locate the IP reputation endpoints under Modules/' }

    class HttpResponseContext {
        [int]$StatusCode
        [object]$Body
    }
    $Accelerators = [PSObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')
    if (-not ('HttpStatusCode' -as [type])) {
        $Accelerators::Add('HttpStatusCode', [System.Net.HttpStatusCode])
    }

    function Get-PSITBecAnalyst { param($Headers) return 'analyste@partner.test' }
    function Write-LogMessage { param($headers, $API, $tenant, $message, $sev, $LogData) }
    function Get-CippException { param($Exception) [PSCustomObject]@{ NormalizedError = [string]$Exception } }
    function Get-PSITIpReputation { param($Ips) }
    function Get-PSITIpReputationKey { param() }
    function Set-PSITIpReputationKey { param($Key, $Analyst) }

    . $ListPath
    . $KeyPath

    function New-IpRequest {
        param([hashtable]$Query = @{}, [hashtable]$Body = @{})
        @{ Headers = @{}; Params = @{ CIPPEndpoint = 'PSITListIpReputation' }; Query = ([PSCustomObject]$Query); Body = ([PSCustomObject]$Body) }
    }
}

Describe 'Invoke-PSITListIpReputation' {
    BeforeEach {
        Mock -CommandName Write-LogMessage -MockWith { }
        Mock -CommandName Get-PSITIpReputation -MockWith {
            [pscustomobject]@{ Rows = @([pscustomobject]@{ Ip = '203.0.113.9'; Score = 87 }); Notes = @() }
        }
    }

    It 'accepts the comma-separated shape and answers rows and notes' {
        $Result = Invoke-PSITListIpReputation -Request (New-IpRequest -Query @{ Ips = '203.0.113.9, 198.51.100.4' }) -TriggerMetadata $null

        $Result.StatusCode | Should -Be ([HttpStatusCode]::OK)
        $Result.Body.Results[0].Score | Should -Be 87
        Should -Invoke Get-PSITIpReputation -Times 1 -ParameterFilter {
            $Ips -contains '203.0.113.9' -and $Ips -contains '198.51.100.4'
        }
    }

    It 'requires at least one address' {
        $Result = Invoke-PSITListIpReputation -Request (New-IpRequest) -TriggerMetadata $null

        $Result.StatusCode | Should -Be ([HttpStatusCode]::BadRequest)
        Should -Invoke Get-PSITIpReputation -Times 0
    }
}

Describe 'Invoke-PSITExecIpReputationKey' {
    BeforeEach {
        Mock -CommandName Write-LogMessage -MockWith { }
        Mock -CommandName Set-PSITIpReputationKey -MockWith { [pscustomobject]@{ Configured = $true; SetUtc = '2026-09-02T10:00:00Z' } }
        Mock -CommandName Get-PSITIpReputationKey -MockWith {
            [pscustomobject]@{ Key = 'secret-key'; SetUtc = '2026-09-01T08:00:00Z'; SetBy = 'a@partner.test' }
        }
    }

    It 'answers the status without ever echoing the key' {
        $Result = Invoke-PSITExecIpReputationKey -Request (New-IpRequest) -TriggerMetadata $null

        $Result.Body.Configured | Should -BeTrue
        $Result.Body.SetBy | Should -Be 'a@partner.test'
        $Result.Body.PSObject.Properties.Name | Should -Not -Contain 'Key'
    }

    It 'stores a key sent in the body, attributed to the caller' {
        $Result = Invoke-PSITExecIpReputationKey -Request (New-IpRequest -Body @{ Key = 'abc' }) -TriggerMetadata $null

        Should -Invoke Set-PSITIpReputationKey -Times 1 -ParameterFilter { $Key -eq 'abc' -and $Analyst -eq 'analyste@partner.test' }
        $Result.Body.Results | Should -Match 'enregistrée'
    }

    It 'says a clear is a clear' {
        Mock -CommandName Set-PSITIpReputationKey -MockWith { [pscustomobject]@{ Configured = $false } }

        $Result = Invoke-PSITExecIpReputationKey -Request (New-IpRequest -Body @{ Key = '' }) -TriggerMetadata $null

        $Result.Body.Results | Should -Match 'effacée'
    }
}
