# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
Builds and stages the Windows x64 SDK MicroVM tests for artifact-only validation.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$BinaryDirectory,

    [Parameter(Mandatory)]
    [string]$Features
)

$ErrorActionPreference = 'Stop'
$binaryDirectoryPath = (Resolve-Path -LiteralPath $BinaryDirectory).Path
$srcRoot = Join-Path $PSScriptRoot '..\..\src'

Push-Location $srcRoot
try {
    $messages = @(cargo test --locked --release --target x86_64-pc-windows-msvc `
        -p mxc-sdk --no-default-features --features $Features `
        --test nvx_e2e --test nvx_phase3_e2e --no-run --message-format=json)
    if ($LASTEXITCODE -ne 0) {
        $messages | ForEach-Object { Write-Host $_ }
        throw "cargo test --no-run failed with exit code $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}

$targets = [ordered]@{
    nvx_e2e = @{
        File = 'nvx-e2e-tests.exe'
        Tests = @(
            'windows_x64::host_only_executor_request_matrix',
            'windows_x64::signed_bundle_executor_configs',
            'windows_x64::signed_bundle_executor_create_and_run',
            'windows_x64::signed_bundle_facade_create_and_run'
        )
    }
    nvx_phase3_e2e = @{
        File = 'nvx-phase3-e2e-tests.exe'
        Tests = @(
            'discovery_without_bundle_is_read_only',
            'powershell_lifecycle_failures_report_both_streams_and_preserve_cleanup',
            'exact_alpha_json_runs_twice_through_signed_nvx_agent',
            'deprovisioning_one_microvm_does_not_disrupt_another',
            'typed_lifecycle_reuses_running_microvm',
            'typed_lifecycle_streams_stdin_stdout_and_cancels',
            'typed_create_and_run_requires_experimental_and_streams',
            'exact_json_lifecycle_routes_microvm_end_to_end',
            'lifecycle_filesystem_policy_is_enforced',
            'lifecycle_directional_network_policy_is_enforced',
            'lifecycle_proxy_routes_guest_http',
            'pty_and_exec_time_proxy_fail_before_workload_launch'
        )
    }
}
$artifacts = @($messages |
    Where-Object { $_.StartsWith('{') } |
    ConvertFrom-Json |
    Where-Object {
        $_.reason -eq 'compiler-artifact' -and $targets.Contains($_.target.name) -and
        $_.profile.test -and $_.executable
    })
foreach ($target in $targets.Keys) {
    $artifact = @($artifacts | Where-Object { $_.target.name -eq $target })
    if ($artifact.Count -ne 1) {
        throw "Expected one $target test executable from cargo; found $($artifact.Count)."
    }
    $destination = Join-Path $binaryDirectoryPath $targets[$target].File
    Copy-Item -LiteralPath $artifact[0].executable -Destination $destination -Force
    $discovered = @(& $destination --list)
    if ($LASTEXITCODE -ne 0) {
        throw "Listing the staged NVX tests failed with exit code $LASTEXITCODE."
    }
    foreach ($name in $targets[$target].Tests) {
        if ($discovered -notcontains "$name`: test") {
            throw "The staged NVX payload did not discover $name."
        }
    }
    Write-Host "Staged SDK MicroVM tests: $destination"
}
$repoRoot = Join-Path $PSScriptRoot '..\..'
$fixtureRoot = Join-Path $binaryDirectoryPath 'nvx-validation\tests'
New-Item -ItemType Directory -Force (Join-Path $fixtureRoot 'scripts'), (Join-Path $fixtureRoot 'configs') | Out-Null
Copy-Item -LiteralPath (Join-Path $repoRoot 'tests\scripts\run_microvm_state_aware_tests.ps1') `
    -Destination (Join-Path $fixtureRoot 'scripts') -Force
Copy-Item -Path (Join-Path $repoRoot 'tests\configs\microvm_*.json') `
    -Destination (Join-Path $fixtureRoot 'configs') -Force
if (-not (Test-Path -LiteralPath (Join-Path $binaryDirectoryPath 'aci-edge-sandboxes\bundle-manifest.json') -PathType Leaf)) {
    throw 'The Windows x64 artifact is missing the signed NVX bundle.'
}
