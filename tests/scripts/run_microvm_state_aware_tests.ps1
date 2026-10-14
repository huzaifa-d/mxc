# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

param(
    [string]$WxcExePath
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $WxcExePath) {
    $WxcExePath = Join-Path $RepoRoot "src\target\x86_64-pc-windows-msvc\debug\wxc-exec.exe"
}
if (-not (Test-Path $WxcExePath -PathType Leaf)) {
    throw "wxc-exec.exe not found at $WxcExePath"
}
if (-not $env:MXC_NVX_BUNDLE_DIR) {
    throw "MXC_NVX_BUNDLE_DIR is required"
}

function Invoke-MicroVmPhase {
    param(
        [string]$Phase,
        [hashtable]$Payload,
        [string]$SandboxId
    )

    $json = $Payload | ConvertTo-Json -Compress -Depth 12
    $base64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
    $arguments = @("--operation", $Phase, "--experimental", "--config-base64", $base64)
    if ($SandboxId) {
        $arguments = @(
            "--operation", $Phase,
            "--container-id", $SandboxId,
            "--experimental",
            "--config-base64", $base64
        )
    }
    $stderr = [IO.Path]::GetTempFileName()
    try {
        $stdout = & $WxcExePath @arguments 2>$stderr
        @{
            ExitCode = $LASTEXITCODE
            Stdout = ($stdout -join "`n")
            Stderr = (Get-Content $stderr -Raw -ErrorAction SilentlyContinue)
        }
    } finally {
        Remove-Item $stderr -Force -ErrorAction SilentlyContinue
    }
}

$provision = Invoke-MicroVmPhase -Phase "provision" -Payload @{
    version = "1.1.0-alpha"
    containment = "microvm"
}
if ($provision.ExitCode -ne 0) {
    throw "provision failed: $($provision.Stderr)"
}
$sandboxId = ($provision.Stdout | ConvertFrom-Json).result.sandboxId
if ($sandboxId -notlike "microvm:*") {
    throw "unexpected sandbox ID: $sandboxId"
}

try {
    $start = Invoke-MicroVmPhase -Phase "start" -SandboxId $sandboxId -Payload @{
        version = "1.1.0-alpha"
    }
    if ($start.ExitCode -ne 0) {
        throw "start failed: $($start.Stderr)"
    }

    $exec = Invoke-MicroVmPhase -Phase "exec" -SandboxId $sandboxId -Payload @{
        version = "1.1.0-alpha"
        process = @{ commandLine = "printf EXECUTOR_NVX_OK" }
    }
    if ($exec.ExitCode -ne 0 -or $exec.Stdout -notmatch "EXECUTOR_NVX_OK") {
        throw "exec failed: exit=$($exec.ExitCode) stdout=$($exec.Stdout) stderr=$($exec.Stderr)"
    }

    $stop = Invoke-MicroVmPhase -Phase "stop" -SandboxId $sandboxId -Payload @{
        version = "1.1.0-alpha"
    }
    if ($stop.ExitCode -ne 0) {
        throw "stop failed: $($stop.Stderr)"
    }
} finally {
    $deprovision = Invoke-MicroVmPhase -Phase "deprovision" -SandboxId $sandboxId -Payload @{
        version = "1.1.0-alpha"
    }
    if ($deprovision.ExitCode -ne 0) {
        throw "deprovision failed: $($deprovision.Stderr)"
    }
}

Write-Host "MicroVM state-aware executor E2E passed: $sandboxId" -ForegroundColor Green
