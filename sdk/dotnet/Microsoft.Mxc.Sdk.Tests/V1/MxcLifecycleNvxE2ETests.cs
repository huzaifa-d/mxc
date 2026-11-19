// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Mxc.Sdk.V1;
using Xunit;
using Dev = Microsoft.Mxc.Sdk.V1.Dev;

namespace Microsoft.Mxc.Sdk.Tests.V1;

[Collection("MxcLiveHost")]
public class MxcLifecycleNvxE2ETests
{
    private const int CaptureHalfLimit = 32 * 1024 * 1024;

    [Fact]
    public async Task DevJson_NvxLifecycleCaptureAndLiveStreams()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows() && RuntimeInformation.ProcessArchitecture == Architecture.X64 &&
            Environment.GetEnvironmentVariable("MXC_ENABLE_NVX_TESTS") == "1", "NVX tests require Windows x64 and MXC_ENABLE_NVX_TESTS=1");
        var options = new Dev.JsonOptions { Experimental = true };
        const string image = "mcr.microsoft.com/azurelinux/base/core:3.0";
        var run = JsonSerializer.Serialize(new { version = "1.1.0-alpha", containment = "microvm", microvm = new { image }, process = new { commandLine = "printf 'NVX_ONESHOT\\n'", timeout = 30000 } });
        var oneShot = await Dev.MxcContainer.RunJsonAsync(run, options, TestContext.Current.CancellationToken);
        Assert.Equal(0, oneShot.ExitCode);
        Assert.Contains("NVX_ONESHOT", oneShot.Stdout);
        var provision = JsonSerializer.Serialize(new { version = "1.1.0-alpha", phase = "provision", containment = "microvm", microvm = new { image } });
        using var response = JsonDocument.Parse(await Dev.MxcLifecycle.ProvisionContainerJsonAsync(provision, options));
        var id = response.RootElement.GetProperty("result").GetProperty("sandboxId").GetString();
        Assert.False(string.IsNullOrEmpty(id));
        string Phase(string phase) => JsonSerializer.Serialize(new { version = "1.0.0", phase, sandboxId = id });
        string Exec(string command, int timeout = 30000) => JsonSerializer.Serialize(new { version = "1.1.0-alpha", phase = "exec", sandboxId = id, process = new { commandLine = command, timeout } });
        string CaptureBoundary(int stderrBytes) => Exec(
            $"head -c {CaptureHalfLimit} /dev/zero && head -c {stderrBytes} /dev/zero >&2", 0);
        async Task AssertCaptureBoundary(int stderrBytes, bool synchronous)
        {
            var request = CaptureBoundary(stderrBytes);
            var result = synchronous
                ? Dev.MxcLifecycle.RunInContainerJson(request, options)
                : await Dev.MxcLifecycle.RunInContainerJsonAsync(request, options, TestContext.Current.CancellationToken);
            Assert.False(result.TimedOut);
            Assert.Equal(0, result.ExitCode);
            Assert.Equal(CaptureHalfLimit, result.Stdout.Length);
            Assert.Equal(stderrBytes, result.Stderr.Length);
            Assert.Equal(-1, result.Stdout.AsSpan().IndexOfAnyExcept('\0'));
            Assert.Equal(-1, result.Stderr.AsSpan().IndexOfAnyExcept('\0'));
        }
        var started = false;
        try
        {
            await Dev.MxcLifecycle.StartContainerJsonAsync(Phase("start"), options);
            started = true;
            var captured = await Dev.MxcLifecycle.RunInContainerJsonAsync(Exec("printf 'NVX_CAPTURE\\n'; printf 'NVX_ERROR\\n' >&2"), options, TestContext.Current.CancellationToken);
            Assert.Equal(0, captured.ExitCode);
            Assert.Contains("NVX_CAPTURE", captured.Stdout);
            Assert.Contains("NVX_ERROR", captured.Stderr);
            await AssertCaptureBoundary(CaptureHalfLimit - 1, synchronous: false);
            await AssertCaptureBoundary(CaptureHalfLimit, synchronous: true);
            var overflow = await Assert.ThrowsAsync<MxcException>(() =>
                Dev.MxcLifecycle.RunInContainerJsonAsync(
                    CaptureBoundary(CaptureHalfLimit + 1), options, TestContext.Current.CancellationToken));
            Assert.Equal(ErrorCode.BackendError, overflow.Code);
            var afterOverflow = await Dev.MxcLifecycle.RunInContainerJsonAsync(
                Exec("printf 'NVX_REUSED\\n'"), options, TestContext.Current.CancellationToken);
            Assert.Equal(0, afterOverflow.ExitCode);
            Assert.Contains("NVX_REUSED", afterOverflow.Stdout);
            using (var largeStream = await Dev.MxcLifecycle.SpawnInContainerJsonAsync(
                Exec($"head -c {2 * CaptureHalfLimit + 1} /dev/zero", 0), options, TestContext.Current.CancellationToken))
            using (var largeOutput = Assert.IsAssignableFrom<Stream>(largeStream.StandardOutput))
            {
                var wait = largeStream.WaitAsync(TestContext.Current.CancellationToken);
                var buffer = new byte[64 * 1024];
                long total = 0;
                int count;
                while ((count = await largeOutput.ReadAsync(buffer, TestContext.Current.CancellationToken)) != 0)
                {
                    total += count;
                }
                Assert.Equal(2L * CaptureHalfLimit + 1, total);
                Assert.Equal(0, (await wait).ExitCode);
            }
            using var process = await Dev.MxcLifecycle.SpawnInContainerJsonAsync(Exec("printf 'NVX_LIVE_OUT\\n'; printf 'NVX_LIVE_ERR\\n' >&2; sleep 3"), options, TestContext.Current.CancellationToken);
            using var stdout = new StreamReader(Assert.IsAssignableFrom<Stream>(process.StandardOutput));
            using var stderr = new StreamReader(Assert.IsAssignableFrom<Stream>(process.StandardError));
            var output = Task.WhenAll(stdout.ReadLineAsync(TestContext.Current.CancellationToken).AsTask(), stderr.ReadLineAsync(TestContext.Current.CancellationToken).AsTask());
            var exit = process.WaitAsync(TestContext.Current.CancellationToken);
            Assert.Same(output, await Task.WhenAny(output, exit));
            var lines = await output;
            Assert.Equal("NVX_LIVE_OUT", lines[0]);
            Assert.Equal("NVX_LIVE_ERR", lines[1]);
            Assert.Equal(0, (await exit).ExitCode);
        }
        finally
        {
            try { if (started) await Dev.MxcLifecycle.StopContainerJsonAsync(Phase("stop"), options); }
            finally { await Dev.MxcLifecycle.DeprovisionContainerJsonAsync(Phase("deprovision"), options); }
        }
    }
}
