# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
Requires discovery and successful completion of the direct-C MicroVM regressions.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc')]
    [string]$Target,

    [string]$LogDirectory
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\TestSuiteResults.ps1')
$srcRoot = Join-Path $PSScriptRoot '..\..\src'
if (-not $LogDirectory) {
    $LogDirectory = Join-Path $srcRoot "target\$Target\release"
}
New-Item -ItemType Directory -Force -Path $LogDirectory | Out-Null
$LogDirectory = (Resolve-Path -LiteralPath $LogDirectory).Path
$required = @(
    'microvm_requests_normalize_exactly_once_on_each_c_surface',
    'permitted_public_spawns_normalize_and_probe_each_surviving_path_once',
    'wrong_entry_points_preserve_the_owning_phase_and_root_errors',
    'pty_dimension_errors_keep_priority_over_json_and_authorization',
    'invalid_lifecycle_pty_dimensions_never_normalize_or_probe',
    'wrong_operation_delegates_normalization_exactly_once',
    'malformed_or_ambiguous_selectors_cannot_bypass_authoritative_validation',
    'escaped_phase_and_selector_keys_reach_backend_validation',
    'lifecycle_pty_preserves_pointer_utf8_and_zero_dimension_precedence',
    'one_shot_pipe_and_stdin_exports_reach_microvm_validation',
    'malformed_contract_version_and_phase_errors_are_preserved',
    'filesystem_validation_preserves_malformed_request_errors',
    'lifecycle_pipe_and_stdin_exports_reach_microvm_validation',
    'pty_exports_reject_microvm',
    'lifecycle_envelope_export_routes_microvm_phases_and_dry_runs',
    'captured_and_attached_lifecycle_exports_match_engine_validation',
    'baseline_microvm_one_shot_capture_still_reaches_the_rust_backend',
    'one_shot_capture_export_cannot_bypass_the_lifecycle_boundary'
)
$modes = @('disabled')
# MicroVM is x64-only; the ARM64 job exercises the feature-off boundary.
if ($Target -eq 'x86_64-pc-windows-msvc') {
    $modes += 'enabled'
}

Push-Location $srcRoot
try {
    foreach ($mode in $modes) {
        $arguments = @(
            'test', '--locked', '--release', '--target', $Target,
            '-p', 'mxc_ffi', '--no-default-features', '--test', 'microvm_json_boundary',
            '--no-run', '--message-format=json'
        )
        if ($mode -eq 'enabled') {
            $arguments += @('--features', 'mxc-sdk/microvm')
        }
        $messages = @(cargo @arguments)
        if ($LASTEXITCODE -ne 0) {
            $messages | ForEach-Object { Write-Host $_ }
            throw "MicroVM C boundary ($mode) compilation failed with exit code $LASTEXITCODE."
        }
        $artifacts = @($messages |
            Where-Object { $_.StartsWith('{') } |
            ConvertFrom-Json |
            Where-Object {
                $_.reason -eq 'compiler-artifact' -and $_.target.name -eq 'microvm_json_boundary' -and
                $_.profile.test -and $_.executable
            })
        if ($artifacts.Count -ne 1) {
            throw "Expected one microvm_json_boundary test executable; found $($artifacts.Count)."
        }
        $executable = $artifacts[0].executable
        $discovered = @(& $executable --list)
        if ($LASTEXITCODE -ne 0) {
            throw "Listing MicroVM C boundary ($mode) failed with exit code $LASTEXITCODE."
        }
        $discovered | Set-Content -LiteralPath (Join-Path $LogDirectory "microvm-json-boundary-$mode-discovery.log")
        foreach ($name in $required) {
            if ($discovered -notcontains "${name}: test") {
                throw "MicroVM C boundary ($mode) did not discover $name."
            }
        }
        $log = Join-Path $LogDirectory "microvm-json-boundary-$mode.log"
        & $executable --test-threads=1 2>&1 | Tee-Object -FilePath $log | Out-Host
        $failure = Get-LibtestFailure -Run @{ ExitCode = $LASTEXITCODE; Log = $log } -RequiredTests $required
        if ($failure) {
            throw "MicroVM C boundary ($mode) $failure."
        }
    }
}
finally {
    Pop-Location
}
