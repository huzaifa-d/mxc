# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

param(
    [string]$WxcExePath,
    [switch]$PrintProvisionPayload
)

$ErrorActionPreference = "Stop"
$ProvisionPayload = @{
    version = "1.1.0-alpha"
    containment = "microvm"
    microvm = @{ image = "mcr.microsoft.com/azurelinux/base/core:3.0" }
}
if ($PrintProvisionPayload) {
    $ProvisionPayload | ConvertTo-Json -Compress -Depth 12
    return
}
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $WxcExePath) {
    $WxcExePath = Join-Path $RepoRoot "src\target\x86_64-pc-windows-msvc\debug\wxc-exec.exe"
}
if (-not (Test-Path $WxcExePath -PathType Leaf)) {
    throw "wxc-exec.exe not found at $WxcExePath"
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
    $process = $null
    try {
        if (-not (Test-Path -LiteralPath $WxcExePath -PathType Leaf)) {
            throw "wxc-exec.exe not found at $WxcExePath"
        }
        # Native stderr becomes a terminating error under Windows PowerShell 5.1.
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $WxcExePath
        $startInfo.Arguments = $arguments -join ' '
        if ([IO.Path]::GetExtension($WxcExePath) -in @('.cmd', '.bat')) {
            $startInfo.FileName = $env:ComSpec
            $startInfo.Arguments = '/d /s /c ""' + $WxcExePath + '" ' + ($arguments -join ' ') + '"'
        }
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $startInfo
        if (-not $process.Start()) {
            throw "Could not start $WxcExePath"
        }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        # Wait only for the executor, not its persistent VM descendants.
        $process.WaitForExit()
        @{
            ExitCode = $process.ExitCode
            Stdout = $stdout.GetAwaiter().GetResult()
            Stderr = $stderr.GetAwaiter().GetResult()
        }
    } finally {
        if ($null -ne $process) {
            $process.Dispose()
        }
    }
}

$provision = Invoke-MicroVmPhase -Phase "provision" -Payload $ProvisionPayload
if ($provision.ExitCode -ne 0) {
    throw "provision failed: exit=$($provision.ExitCode) stdout=$($provision.Stdout) stderr=$($provision.Stderr)"
}
$sandboxId = ($provision.Stdout | ConvertFrom-Json).result.sandboxId
if ($sandboxId -notlike "microvm:*") {
    throw "unexpected sandbox ID: $sandboxId"
}

$primaryError = $null
try {
    $start = Invoke-MicroVmPhase -Phase "start" -SandboxId $sandboxId -Payload @{
        version = "1.1.0-alpha"
    }
    if ($start.ExitCode -ne 0) {
        throw "start failed: exit=$($start.ExitCode) stdout=$($start.Stdout) stderr=$($start.Stderr)"
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
        throw "stop failed: exit=$($stop.ExitCode) stdout=$($stop.Stdout) stderr=$($stop.Stderr)"
    }
} catch {
    $primaryError = $_
    throw
} finally {
    try {
        $deprovision = Invoke-MicroVmPhase -Phase "deprovision" -SandboxId $sandboxId -Payload @{
            version = "1.1.0-alpha"
        }
        if ($deprovision.ExitCode -ne 0) {
            throw "deprovision failed: exit=$($deprovision.ExitCode) stdout=$($deprovision.Stdout) stderr=$($deprovision.Stderr)"
        }
    } catch {
        if ($null -ne $primaryError) {
            throw "Primary lifecycle failure: $primaryError`nDeprovision cleanup failure: $_"
        }
        throw
    }
}

Write-Host "MicroVM state-aware executor E2E passed: $sandboxId" -ForegroundColor Green
Write-Host "VM_EXECUTED executor lifecycle provision/start/exec/stop/deprovision"
