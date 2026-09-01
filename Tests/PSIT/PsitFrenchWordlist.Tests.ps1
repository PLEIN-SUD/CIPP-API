# Pester tests for the French passphrase wordlist and the language setting that serves it.
#
# The list is public by design, like upstream's words.txt: passphrase strength lives in the
# cryptographic draw, never in list secrecy. What is pinned here: the floor that keeps the
# draw strong (list size), the shape the generator filter requires (a word outside [a-z]
# would be dropped silently and shrink the pool), the setting contract (french draws French,
# anything else draws upstream English), and the fallback: a missing French file must never
# fail a password reset - it falls back to the English list.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/GraphHelper/New-passwordString.ps1')

    $script:WordlistPath = Join-Path $RepoRoot 'Config/psit-mots.txt'
    $script:Words = @(Get-Content $script:WordlistPath -Encoding UTF8 | Where-Object { $_.Length -gt 0 -and $_ -match '^[a-zA-Z]+$' })
    $script:FrenchPool = [System.Collections.Generic.HashSet[string]]::new([string[]]$script:Words)
    $script:EnglishPool = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@(Get-Content (Join-Path $RepoRoot 'Config/words.txt') -Encoding UTF8 |
                Where-Object { $_.Length -gt 0 -and $_ -match '^[a-zA-Z]+$' } |
                ForEach-Object { $_.ToLowerInvariant() })
    )

    function Get-CippTable { param($tablename) @{} }
    function Get-CIPPAzDataTableEntity { $script:MockSettings }

    function Get-PassphraseParts {
        param([string]$Passphrase)
        @($Passphrase -split '-' | ForEach-Object { ($_ -replace '[^a-zA-Z]', '').ToLowerInvariant() })
    }

    $script:SavedRootPath = $env:CIPPRootPath
    $env:CIPPRootPath = $RepoRoot
}

AfterAll {
    $env:CIPPRootPath = $script:SavedRootPath
}

Describe 'Config/psit-mots.txt' {
    It 'holds at least 3000 usable words, so four words draw beyond 46 bits' {
        $script:Words.Count | Should -BeGreaterThan 2999
    }

    It 'keeps every word lowercase ascii, 4 to 12 letters: nothing the filter would drop' {
        $Offenders = @($script:Words | Where-Object { $_ -cnotmatch '^[a-z]{4,12}$' })
        $Offenders | Should -BeNullOrEmpty
    }

    It 'holds no duplicate, because a duplicate silently shrinks the pool' {
        ($script:Words | Sort-Object -Unique).Count | Should -Be $script:Words.Count
    }

    It 'carries no byte outside printable ascii: accent-free is the contract' {
        $Raw = [System.IO.File]::ReadAllBytes($script:WordlistPath)
        @($Raw | Where-Object { $_ -gt 126 }) | Should -BeNullOrEmpty
    }
}

Describe 'New-passwordString and the passphrase language setting' {
    BeforeEach {
        $script:MockSettings = [pscustomobject]@{
            passwordType       = 'Passphrase'
            wordCount          = 4
            capitalizeWords    = 'true'
            appendNumber       = 'true'
            appendSpecialChar  = 'false'
            passphraseLanguage = 'french'
        }
    }


    It 'french draws French words, capitalized, with the appended number' {
        $Passphrase = New-passwordString
        $Parts = Get-PassphraseParts $Passphrase
        $Parts.Count | Should -Be 4
        foreach ($Part in $Parts) {
            $script:FrenchPool.Contains($Part) | Should -BeTrue -Because "'$Part' should come from psit-mots.txt"
        }
        $Passphrase | Should -Match '\d'
        $Passphrase | Should -MatchExactly '[A-Z]'
    }

    It 'no language stored, and the upstream English list answers as before' {
        $script:MockSettings = [pscustomobject]@{
            passwordType      = 'Passphrase'
            wordCount         = 4
            capitalizeWords   = 'true'
            appendNumber      = 'true'
            appendSpecialChar = 'false'
        }
        $Parts = Get-PassphraseParts (New-passwordString)
        $Parts.Count | Should -Be 4
        foreach ($Part in $Parts) {
            $script:EnglishPool.Contains($Part) | Should -BeTrue -Because "'$Part' should come from words.txt"
        }
    }

    It 'french selected but the file absent: English answers, the reset never fails' {
        $TempRoot = Join-Path $TestDrive 'root'
        New-Item -Path (Join-Path $TempRoot 'Config') -ItemType Directory -Force | Out-Null
        Copy-Item (Join-Path $env:CIPPRootPath 'Config/words.txt') (Join-Path $TempRoot 'Config/words.txt')

        $Saved = $env:CIPPRootPath
        try {
            $env:CIPPRootPath = $TempRoot
            $Parts = Get-PassphraseParts (New-passwordString)
            $Parts.Count | Should -Be 4
            foreach ($Part in $Parts) {
                $script:EnglishPool.Contains($Part) | Should -BeTrue -Because "'$Part' should come from words.txt"
            }
        } finally {
            $env:CIPPRootPath = $Saved
        }
    }
}
