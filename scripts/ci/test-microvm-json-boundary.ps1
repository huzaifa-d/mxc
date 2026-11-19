# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
Requires the direct-C MicroVM boundary tests to be discovered and pass.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc')]
    [string]$Target,

    [Parameter(Mandatory)]
    [string]$LogDirectory
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\TestSuiteResults.ps1')
$required = @(
    'microvm_creation_requires_opt_in_and_rejects_lifecycle_envelopes',
    'microvm_lifecycle_exec_exports_require_opt_in',
    'microvm_pty_exports_reject_unsupported_modes',
    'microvm_ambiguous_selectors_are_rejected_at_c_boundary'
)
New-Item -ItemType Directory -Force -Path $LogDirectory | Out-Null
$log = Join-Path (Resolve-Path -LiteralPath $LogDirectory).Path 'microvm-json-boundary.log'

Push-Location (Join-Path $PSScriptRoot '..\..\src')
try {
    $messages = @(cargo test --locked --release --target $Target -p mxc_ffi `
        --no-default-features --test microvm_json_boundary --no-run --message-format=json)
    if ($LASTEXITCODE -ne 0) {
        $messages | ForEach-Object { Write-Host $_ }
        throw "MicroVM C boundary compilation failed with exit code $LASTEXITCODE."
    }
    $artifacts = @($messages |
        Where-Object { $_.StartsWith('{') } |
        ConvertFrom-Json |
        Where-Object {
            $_.reason -eq 'compiler-artifact' -and $_.target.name -eq 'microvm_json_boundary' -and
            $_.profile.test -and $_.executable
        })
    if ($artifacts.Count -ne 1) {
        throw "Expected one MicroVM C boundary executable; found $($artifacts.Count)."
    }
    $discovered = @(& $artifacts[0].executable --list)
    if ($LASTEXITCODE -ne 0) {
        throw "Listing MicroVM C boundary tests failed with exit code $LASTEXITCODE."
    }
    foreach ($name in $required) {
        if ($discovered -notcontains "${name}: test") {
            throw "MicroVM C boundary did not discover $name."
        }
    }
    & $artifacts[0].executable --test-threads=1 2>&1 | Tee-Object -FilePath $log | Out-Host
    $failure = Get-LibtestFailure -Run @{ ExitCode = $LASTEXITCODE; Log = $log } -RequiredTests $required
    if ($failure) {
        throw "MicroVM C boundary $failure."
    }
}
finally {
    Pop-Location
}
