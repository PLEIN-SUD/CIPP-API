# Pester tests for the breach-exposure snapshot stored in the BEC dossier.
#
# The service is injected, so nothing here reaches Have I Been Pwned. That is not only about speed:
# the real endpoint is authenticated, quota-limited, and would carry a mailbox address to a third
# party. A test that needs a production credential to run is a test nobody runs.
#
# What matters most here is the four states. "No exposure referenced" and "we could not look" render
# as different sentences in a document a client reads, so they must be different states in the data.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/PSIT/Get-PSITBecBreachExposure.ps1')

    # A breach as HIBP's breachedaccount?truncateResponse=false returns it, including the fields
    # the whitelist has to drop.
    function New-Breach {
        param(
            $Name,
            $Title,
            $BreachDate,
            $DataClasses = @('Email addresses'),
            $LogoPath = 'https://logos.test/logo.png'
        )
        [pscustomobject]@{
            Name         = $Name
            Title        = $Title ?? $Name
            Domain       = "$Name.test"
            BreachDate   = $BreachDate
            AddedDate    = '2019-01-01T00:00:00Z'
            PwnCount     = 1234567
            Description  = '<p>Long HTML description that has no business in the dossier.</p>'
            DataClasses  = $DataClasses
            LogoPath     = $LogoPath
            IsVerified   = $true
            IsSensitive  = $false
        }
    }

    # No logo unless a test asks for one: the fetch is the only part that touches the network.
    $script:NoLogo = { param($Url) throw 'no logo in tests' }

    # A well-formed PNG of a chosen size: signature, filler, IEND. The size tests are about the
    # caps, so their fixtures must pass the format check rather than fail it for the wrong reason.
    function New-PngBytes {
        param([int]$Size = 64)
        $Head = [byte[]](137, 80, 78, 71, 13, 10, 26, 10)
        $Tail = [byte[]](0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130)
        $Filler = [byte[]]::new([Math]::Max($Size - $Head.Length - $Tail.Length, 1))
        return $Head + $Filler + $Tail
    }
}

Describe 'Get-PSITBecBreachExposure' {
    Context 'the four states' {
        It 'state 1: exposure with passwords, aggregated over the years' {
            $Request = {
                param($Endpoint)
                @(
                    (New-Breach -Name 'Adobe' -BreachDate '2013-10-04' -DataClasses @('Email addresses', 'Password hints', 'Passwords')),
                    (New-Breach -Name 'Dropbox' -BreachDate '2012-07-01' -DataClasses @('Email addresses', 'Passwords')),
                    (New-Breach -Name 'Forum' -BreachDate '2021-03-15' -DataClasses @('Email addresses'))
                )
            }

            $Result = Get-PSITBecBreachExposure -Addresses @('p.martin@contoso.test') -RequestCommand $Request -LogoCommand $script:NoLogo

            $Result.Status | Should -Be 'ok'
            $Result.BreachCount | Should -Be 3
            $Result.PasswordCount | Should -Be 2
            $Result.YearMin | Should -Be 2012
            $Result.YearMax | Should -Be 2021
        }

        It 'state 2: exposure with no password class at all' {
            $Request = {
                param($Endpoint)
                @((New-Breach -Name 'Forum' -BreachDate '2021-03-15' -DataClasses @('Email addresses', 'Usernames')))
            }

            $Result = Get-PSITBecBreachExposure -Addresses @('p.martin@contoso.test') -RequestCommand $Request -LogoCommand $script:NoLogo

            $Result.Status | Should -Be 'ok'
            $Result.BreachCount | Should -Be 1
            $Result.PasswordCount | Should -Be 0
        }

        It 'state 3: no breach referenced, which is an answer and not a failure' {
            # 404 from HIBP means "this account is in nothing we know of", and Get-HIBPRequest
            # already turns it into an empty array.
            $Request = { param($Endpoint) @() }

            $Result = Get-PSITBecBreachExposure -Addresses @('p.martin@contoso.test') -RequestCommand $Request -LogoCommand $script:NoLogo

            $Result.Status | Should -Be 'ok'
            $Result.BreachCount | Should -Be 0
            $Result.PasswordCount | Should -Be 0
            $Result.YearMin | Should -BeNullOrEmpty
        }

        It 'state 4a: the service is not configured for this instance' {
            $Request = { param($Endpoint) throw 'Failed to connect to HIBP: The remote server returned an error: (401) Unauthorized.' }

            $Result = Get-PSITBecBreachExposure -Addresses @('p.martin@contoso.test') -RequestCommand $Request -LogoCommand $script:NoLogo

            $Result.Status | Should -Be 'not-configured'
            $Result.Reason | Should -Not -BeNullOrEmpty
            $Result.BreachCount | Should -Be 0
        }

        It 'state 4b: the service is unreachable' {
            $Request = { param($Endpoint) throw 'Failed to connect to HIBP: The operation has timed out.' }

            $Result = Get-PSITBecBreachExposure -Addresses @('p.martin@contoso.test') -RequestCommand $Request -LogoCommand $script:NoLogo

            $Result.Status | Should -Be 'error'
            $Result.Reason | Should -Be 'service indisponible'
        }

        It 'state 4c: the quota is reached, and the reply is not mistaken for a breach' {
            # The trap this test exists for: Get-HIBPRequest returns a single OBJECT on 429, so
            # @($Raw) is a one-element array that looks exactly like one breach.
            $Request = { param($Endpoint) @{ Wait = '4'; 'rate-limit' = $true } }

            $Result = Get-PSITBecBreachExposure -Addresses @('p.martin@contoso.test') -RequestCommand $Request -LogoCommand $script:NoLogo

            $Result.Status | Should -Be 'rate-limited'
            $Result.BreachCount | Should -Be 0
            $Result.RetryAfter | Should -Be '4'
        }
    }

    Context 'nothing sensitive reaches the dossier' {
        It 'keeps four fields and drops everything else, description included' {
            $Request = {
                param($Endpoint)
                @((New-Breach -Name 'Adobe' -BreachDate '2013-10-04' -DataClasses @('Email addresses', 'Passwords')))
            }

            $Result = Get-PSITBecBreachExposure -Addresses @('p.martin@contoso.test') -RequestCommand $Request -LogoCommand $script:NoLogo
            $Keys = @($Result.Breaches[0].Keys)

            $Keys | Should -Contain 'Name'
            $Keys | Should -Contain 'BreachDate'
            $Keys | Should -Contain 'DataClasses'
            $Keys | Should -Contain 'Password'
            $Keys | Should -Not -Contain 'Description'
            $Keys | Should -Not -Contain 'PwnCount'
            $Keys | Should -Not -Contain 'Domain'
            $Keys | Should -Not -Contain 'LogoUrl'
            @($Keys).Count | Should -Be 4
        }

        It 'never copies a password value, even when the response carries one' {
            # The account endpoint returns none. The domain-wide proxy does, and this proves that a
            # response shaped like that one still cannot put a fragment in the dossier.
            $WithPassword = New-Breach -Name 'Adobe' -BreachDate '2013-10-04' -DataClasses @('Passwords')
            $WithPassword | Add-Member -NotePropertyName 'password' -NotePropertyValue 'hunter2*'
            $Request = { param($Endpoint) @($WithPassword) }

            $Result = Get-PSITBecBreachExposure -Addresses @('p.martin@contoso.test') -RequestCommand $Request -LogoCommand $script:NoLogo
            $Json = $Result | ConvertTo-Json -Depth 10

            $Json | Should -Not -Match 'hunter2'
            # -contains is case-insensitive, so it cannot tell the dropped lowercase `password`
            # value from the kept `Password` boolean. Compare the exact strings.
            @($Result.Breaches[0].Keys | Where-Object { $_ -ceq 'password' }) | Should -BeNullOrEmpty
            @($Result.Breaches[0].Keys | Where-Object { $_ -ceq 'Password' }) | Should -Not -BeNullOrEmpty
            $Result.Breaches[0].Password | Should -BeTrue
        }

        It 'derives the password flag from the data classes, whatever their case' {
            $Request = {
                param($Endpoint)
                @(
                    (New-Breach -Name 'A' -BreachDate '2013-01-01' -DataClasses @('Passwords')),
                    (New-Breach -Name 'B' -BreachDate '2014-01-01' -DataClasses @('Historical passwords')),
                    (New-Breach -Name 'C' -BreachDate '2015-01-01' -DataClasses @('Email addresses'))
                )
            }

            $Result = Get-PSITBecBreachExposure -Addresses @('p.martin@contoso.test') -RequestCommand $Request -LogoCommand $script:NoLogo

            $Result.PasswordCount | Should -Be 2
        }
    }

    Context 'the addresses looked up' {
        It 'deduplicates the UPN and its aliases, ignoring case' {
            $script:Calls = @()
            $Request = {
                param($Endpoint)
                $script:Calls += $Endpoint
                @()
            }

            $Result = Get-PSITBecBreachExposure -RequestCommand $Request -LogoCommand $script:NoLogo -Addresses @(
                'p.martin@contoso.test',
                'P.Martin@contoso.test',
                ' p.martin@contoso.test ',
                'pm@contoso.test'
            )

            @($script:Calls).Count | Should -Be 2
            @($Result.Addresses).Count | Should -Be 2
        }

        It 'merges the same breach found on two addresses into one' {
            $Request = {
                param($Endpoint)
                if ($Endpoint -match 'pm%40') {
                    @(
                        (New-Breach -Name 'Adobe' -BreachDate '2013-10-04' -DataClasses @('Passwords')),
                        (New-Breach -Name 'Forum' -BreachDate '2021-01-01')
                    )
                } else {
                    @((New-Breach -Name 'Adobe' -BreachDate '2013-10-04' -DataClasses @('Passwords')))
                }
            }

            $Result = Get-PSITBecBreachExposure -RequestCommand $Request -LogoCommand $script:NoLogo -Addresses @(
                'p.martin@contoso.test',
                'pm@contoso.test'
            )

            # Three lookups' worth of rows, two distinct compromises.
            $Result.BreachCount | Should -Be 2
            $Result.PasswordCount | Should -Be 1
        }

        It 'caps how many addresses it queries and says how many it had' {
            $script:Count = 0
            $Request = { param($Endpoint) $script:Count++; @() }

            $Result = Get-PSITBecBreachExposure -RequestCommand $Request -LogoCommand $script:NoLogo -MaxAddresses 2 -Addresses @(
                'a@contoso.test', 'b@contoso.test', 'c@contoso.test', 'd@contoso.test'
            )

            $script:Count | Should -Be 2
            @($Result.Addresses).Count | Should -Be 2
            $Result.AddressesTotal | Should -Be 4
            $Result.AddressesSkipped | Should -Be 2
        }

        It 'drops anything that is not an address rather than querying it' {
            $script:Calls = @()
            $Request = { param($Endpoint) $script:Calls += $Endpoint; @() }

            $Result = Get-PSITBecBreachExposure -RequestCommand $Request -LogoCommand $script:NoLogo -Addresses @(
                'p.martin@contoso.test', 'SPO:SPO_guid', '', $null, 'X500:/o=ExchangeLabs'
            )

            @($script:Calls).Count | Should -Be 1
            @($Result.Addresses).Count | Should -Be 1
        }

        It 'reports an error rather than a clean nothing when no address is usable' {
            $Request = { param($Endpoint) throw 'should not be called' }

            $Result = Get-PSITBecBreachExposure -Addresses @('', $null) -RequestCommand $Request -LogoCommand $script:NoLogo

            $Result.Status | Should -Be 'error'
            $Result.Reason | Should -Be 'aucune adresse exploitable'
        }

        It 'escapes the address into the endpoint' {
            $script:Calls = @()
            $Request = { param($Endpoint) $script:Calls += $Endpoint; @() }

            $null = Get-PSITBecBreachExposure -Addresses @('p+martin@contoso.test') -RequestCommand $Request -LogoCommand $script:NoLogo

            $script:Calls[0] | Should -BeLike '*p%2Bmartin%40contoso.test*'
            $script:Calls[0] | Should -BeLike '*truncateResponse=false*'
        }
    }

    Context 'edge shapes the report has to survive' {
        It 'keeps a breach with no date, and leaves the year range to the others' {
            $Request = {
                param($Endpoint)
                @(
                    (New-Breach -Name 'Undated' -BreachDate $null),
                    (New-Breach -Name 'Dated' -BreachDate '2015-06-01')
                )
            }

            $Result = Get-PSITBecBreachExposure -Addresses @('p.martin@contoso.test') -RequestCommand $Request -LogoCommand $script:NoLogo

            $Result.BreachCount | Should -Be 2
            $Result.YearMin | Should -Be 2015
            $Result.YearMax | Should -Be 2015
            ($Result.Breaches | Where-Object { $_.Name -eq 'Undated' }).BreachDate | Should -BeNullOrEmpty
        }

        It 'leaves the year range empty when no breach carries a date' {
            $Request = { param($Endpoint) @((New-Breach -Name 'Undated' -BreachDate $null)) }

            $Result = Get-PSITBecBreachExposure -Addresses @('p.martin@contoso.test') -RequestCommand $Request -LogoCommand $script:NoLogo

            $Result.BreachCount | Should -Be 1
            $Result.YearMin | Should -BeNullOrEmpty
            $Result.YearMax | Should -BeNullOrEmpty
        }

        It 'holds a breach with no data classes' {
            $Request = { param($Endpoint) @((New-Breach -Name 'Bare' -BreachDate '2018-01-01' -DataClasses @())) }

            $Result = Get-PSITBecBreachExposure -Addresses @('p.martin@contoso.test') -RequestCommand $Request -LogoCommand $script:NoLogo

            @($Result.Breaches[0].DataClasses).Count | Should -Be 0
            $Result.Breaches[0].Password | Should -BeFalse
        }

        It 'drops a breach with neither name nor title' {
            $Request = {
                param($Endpoint)
                @(
                    ([pscustomobject]@{ BreachDate = '2018-01-01'; DataClasses = @('Passwords') }),
                    (New-Breach -Name 'Real' -BreachDate '2018-01-01')
                )
            }

            $Result = Get-PSITBecBreachExposure -Addresses @('p.martin@contoso.test') -RequestCommand $Request -LogoCommand $script:NoLogo

            $Result.BreachCount | Should -Be 1
            $Result.Breaches[0].Name | Should -Be 'Real'
        }

        It 'stamps the check in UTC and names its source' {
            $Request = { param($Endpoint) @() }

            $Result = Get-PSITBecBreachExposure -Addresses @('p.martin@contoso.test') -RequestCommand $Request -LogoCommand $script:NoLogo

            $Result.CheckedUtc | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$'
            $Result.Source | Should -BeLike '*Have I Been Pwned*'
        }
    }

    Context 'logos, which must never be the reason a collection fails' {
        It 'stores a small logo as a data URI' {
            $Request = { param($Endpoint) @((New-Breach -Name 'Adobe' -BreachDate '2013-10-04')) }
            $Logo = { param($Url) [pscustomobject]@{ Bytes = (New-PngBytes -Size 64); ContentType = 'image/png' } }

            $Result = Get-PSITBecBreachExposure -Addresses @('p.martin@contoso.test') -RequestCommand $Request -LogoCommand $Logo

            $Result.Breaches[0].Logo | Should -BeLike 'data:image/png;base64,*'
        }

        It 'skips a logo over the per-image cap' {
            $Request = { param($Endpoint) @((New-Breach -Name 'Adobe' -BreachDate '2013-10-04')) }
            $Logo = { param($Url) [pscustomobject]@{ Bytes = (New-PngBytes -Size 20000); ContentType = 'image/png' } }

            $Result = Get-PSITBecBreachExposure -Addresses @('p.martin@contoso.test') -RequestCommand $Request -LogoCommand $Logo -MaxLogoBytes 12000

            @($Result.Breaches[0].Keys) | Should -Not -Contain 'Logo'
            $Result.BreachCount | Should -Be 1
        }

        It 'stops fetching logos once the total budget is spent, and keeps the breaches' {
            $Request = {
                param($Endpoint)
                @(1..5 | ForEach-Object { New-Breach -Name "Breach$_" -BreachDate '2015-01-01' })
            }
            $Logo = { param($Url) [pscustomobject]@{ Bytes = (New-PngBytes -Size 4000); ContentType = 'image/png' } }

            $Result = Get-PSITBecBreachExposure -Addresses @('p.martin@contoso.test') -RequestCommand $Request -LogoCommand $Logo -MaxLogoTotalBytes 9000

            $Result.BreachCount | Should -Be 5
            @($Result.Breaches | Where-Object { $_.Keys -contains 'Logo' }).Count | Should -Be 2
        }

        It 'refuses a truncated image, because react-pdf hangs on one instead of raising' {
            # Found the hard way: a malformed PNG made two renders sit at their 120-second timeout
            # with no error, until zlib surfaced Z_DATA_ERROR from an unresolved promise. A logo is
            # decoration; a decoration that can freeze report generation is not acceptable.
            $Request = { param($Endpoint) @((New-Breach -Name 'Adobe' -BreachDate '2013-10-04')) }
            $Header = [byte[]](137, 80, 78, 71, 13, 10, 26, 10)
            $Truncated = { param($Url) [pscustomobject]@{ Bytes = $Header + [byte[]]::new(40); ContentType = 'image/png' } }

            $Result = Get-PSITBecBreachExposure -Addresses @('p.martin@contoso.test') -RequestCommand $Request -LogoCommand $Truncated

            @($Result.Breaches[0].Keys) | Should -Not -Contain 'Logo'
            $Result.BreachCount | Should -Be 1
        }

        It 'refuses bytes that are not a PNG at all' {
            $Request = { param($Endpoint) @((New-Breach -Name 'Adobe' -BreachDate '2013-10-04')) }
            $NotPng = { param($Url) [pscustomobject]@{ Bytes = [byte[]][char[]]'<html>not an image</html>'; ContentType = 'image/png' } }

            $Result = Get-PSITBecBreachExposure -Addresses @('p.martin@contoso.test') -RequestCommand $Request -LogoCommand $NotPng

            @($Result.Breaches[0].Keys) | Should -Not -Contain 'Logo'
        }

        It 'accepts a complete PNG' {
            $Request = { param($Endpoint) @((New-Breach -Name 'Adobe' -BreachDate '2013-10-04')) }
            # Signature, a filler body, then a well-formed IEND chunk.
            $Png = { param($Url)
                $Bytes = [byte[]](137, 80, 78, 71, 13, 10, 26, 10) + [byte[]]::new(30) +
                    [byte[]](0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130)
                [pscustomobject]@{ Bytes = $Bytes; ContentType = 'image/png' }
            }

            $Result = Get-PSITBecBreachExposure -Addresses @('p.martin@contoso.test') -RequestCommand $Request -LogoCommand $Png

            $Result.Breaches[0].Logo | Should -BeLike 'data:image/png;base64,*'
        }

        It 'survives a logo fetch that throws' {
            $Request = { param($Endpoint) @((New-Breach -Name 'Adobe' -BreachDate '2013-10-04')) }
            $Logo = { param($Url) throw 'CDN down' }

            $Result = Get-PSITBecBreachExposure -Addresses @('p.martin@contoso.test') -RequestCommand $Request -LogoCommand $Logo

            $Result.Status | Should -Be 'ok'
            $Result.BreachCount | Should -Be 1
            @($Result.Breaches[0].Keys) | Should -Not -Contain 'Logo'
        }
    }
}
