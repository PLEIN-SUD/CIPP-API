# Pester test for the one invariant the rest of this suite cannot see.
#
# Every other test here dot-sources the file it exercises, so a function is always in scope and
# always resolves. Production does not work that way: CIPPCore exports by file basename
# (Export-ModuleMember -Function $Public.BaseName), and CIPPHTTP is a separate module that can
# only call what CIPPCore exported. A second function tucked into someone else's file is loaded,
# usable from inside CIPPCore, and invisible from an endpoint.
#
# That is exactly how the ingestion secret shipped broken: rotating it answered "the term
# Set-PSITSocWebhookSecret is not recognized", with 173 green tests behind it. This test walks the
# endpoints and checks that every PSIT command they call has a file of its own to be exported by.

BeforeAll {
    $script:RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:CorePath = Join-Path $script:RepoRoot 'Modules/CIPPCore/Public/PSIT'
    $script:HttpPath = Join-Path $script:RepoRoot 'Modules/CIPPHTTP/Public/Entrypoints/HTTP Functions'

    $script:Exported = @(Get-ChildItem -Path $script:CorePath -Filter '*.ps1' | ForEach-Object { $_.BaseName })
    $script:Endpoints = @(Get-ChildItem -Path $script:HttpPath -Filter 'Invoke-*PSIT*.ps1' -Recurse)
}

Describe 'PSIT module exports' {
    It 'actually found the files it checks' {
        # Without this, a wrong path makes both checks below pass on an empty collection, which
        # is how a guard becomes decoration. The first version of this file did exactly that.
        $script:Exported.Count | Should -BeGreaterThan 15
        $script:Endpoints.Count | Should -BeGreaterThan 10
    }

    It 'gives every PSIT command an endpoint calls a file of its own' {
        $Missing = [System.Collections.Generic.List[string]]::new()

        foreach ($Endpoint in $script:Endpoints) {
            $Content = Get-Content -Path $Endpoint.FullName -Raw
            $Called = [regex]::Matches($Content, '\b(?:Get|Set|New|Add|Remove|Test|Resolve|Revoke|Close|Invoke|ConvertFrom)-PSIT[A-Za-z]+') |
                ForEach-Object { $_.Value } |
                Select-Object -Unique

            foreach ($Command in $Called) {
                # An endpoint calling another endpoint is not a CIPPCore export.
                if ($Command -like 'Invoke-PSIT*' -and @($script:Endpoints.BaseName) -contains $Command) { continue }
                if ($script:Exported -contains $Command) { continue }
                $Missing.Add("$($Endpoint.BaseName) calls $Command, which has no file in Modules/CIPPCore/Public/PSIT")
            }
        }

        $Missing | Should -BeNullOrEmpty
    }

    It 'names each core file after a function it actually defines' {
        # The export is the basename. A file whose basename matches nothing inside it exports a
        # command that does not exist, which fails at the call site rather than at load.
        $Wrong = [System.Collections.Generic.List[string]]::new()

        foreach ($File in Get-ChildItem -Path $script:CorePath -Filter '*.ps1') {
            $Content = Get-Content -Path $File.FullName -Raw
            if ($Content -notmatch "(?m)^function\s+$([regex]::Escape($File.BaseName))\b") {
                $Wrong.Add("$($File.Name) defines no function named $($File.BaseName)")
            }
        }

        $Wrong | Should -BeNullOrEmpty
    }
}
