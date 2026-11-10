// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.V1;
using Microsoft.Mxc.Sdk.Native;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests;

/// <summary>
/// The marshalling step itself: a populated native detail becoming an
/// <see cref="MxcException"/>.
/// </summary>
/// <remarks>
/// <see cref="MxcExceptionTests"/> covers the halves either side of this one —
/// the managed exception's own behaviour, and the all-null detail that a
/// library-raised failure produces. Neither reaches
/// <c>NativeError.ToException</c> with the call fields filled, because the
/// native layer only fills them when a real platform API fails, which needs a
/// prepared host and a backend. So nothing pinned the field-to-property
/// mapping: transposing <c>operation_utf8</c> and <c>native_code_utf8</c> in
/// the marshalling left the whole suite green. Every value below is distinct
/// so that a transposition fails.
/// </remarks>
public unsafe class NativeErrorTests
{
    /// <summary>
    /// Allocate a native UTF-8 string, keeping <see langword="null"/> distinct
    /// from the empty string — the distinction the native contract rests on.
    /// </summary>
    private static byte* Utf8(string? value) =>
        value is null ? null : (byte*)Marshal.StringToCoTaskMemUTF8(value);

    private static MxcErrorDetail Detail(
        string? message,
        string? operation = null,
        string? nativeCode = null,
        string? remediation = null) =>
        new()
        {
            message_utf8 = Utf8(message),
            operation_utf8 = Utf8(operation),
            native_code_utf8 = Utf8(nativeCode),
            remediation_utf8 = Utf8(remediation),
        };

    /// <summary>
    /// Releases what <see cref="Utf8"/> allocated. Freeing a null pointer is a
    /// no-op, so every field can be released unconditionally.
    /// </summary>
    /// <remarks>
    /// Test-owned memory: it was allocated here, so it is freed here. Product
    /// code never does this — a real detail is allocated by the native layer and
    /// released back to it, by <c>mxc_error_detail_free</c> when the detail
    /// stands alone or by the owning result's free function when it is embedded
    /// in one, because only the allocator that produced a pointer can free it.
    /// </remarks>
    private static void Free(MxcErrorDetail detail)
    {
        Marshal.FreeCoTaskMem((IntPtr)detail.message_utf8);
        Marshal.FreeCoTaskMem((IntPtr)detail.operation_utf8);
        Marshal.FreeCoTaskMem((IntPtr)detail.native_code_utf8);
        Marshal.FreeCoTaskMem((IntPtr)detail.remediation_utf8);
    }

    [Fact]
    public void LifecycleDetailsAreDetachedAndNotIncludedInExceptionText()
    {
        var detail = Detail("cleanup failed for private-id", "operation private-id", "code private-id", "fix private-id");
        var json = Utf8("{\"nvxRecovery\":{\"sandboxId\":\"private-id\",\"state\":\"provisioned\"}}");
        MxcException ex;
        try
        {
            ex = NativeError.ToExceptionWithDetails((int)ErrorCode.BackendError, detail, "fallback", json);
        }
        finally
        {
            Free(detail);
            Marshal.FreeCoTaskMem((IntPtr)json);
        }
        var details = Assert.IsType<JsonElement>(ex.Data["details"]);
        Assert.Equal("private-id", details.GetProperty("nvxRecovery").GetProperty("sandboxId").GetString());
        Assert.DoesNotContain("private-id", ex.Message);
        Assert.DoesNotContain("private-id", ex.ToString());
        Assert.DoesNotContain("private-id", ex.Operation);
        Assert.DoesNotContain("private-id", ex.NativeCode);
        Assert.DoesNotContain("private-id", ex.Remediation);
    }

    [Theory]
    [InlineData("{")]
    [InlineData("[]")]
    [InlineData("null")]
    public void InvalidLifecycleDetailsPreserveTheOriginalException(string jsonText)
    {
        var detail = Detail("original failure");
        var json = Utf8(jsonText);
        try
        {
            var ex = NativeError.ToExceptionWithDetails((int)ErrorCode.NotProvisioned, detail, "fallback", json);
            Assert.Equal(ErrorCode.BackendError, ex.Code);
            var original = Assert.IsType<MxcException>(ex.InnerException);
            Assert.Equal(ErrorCode.NotProvisioned, original.Code);
            Assert.Equal("original error message withheld because native error details were malformed", original.Message);
        }
        finally
        {
            Free(detail);
            Marshal.FreeCoTaskMem((IntPtr)json);
        }
    }

    [Theory]
    [InlineData("{\"nvxRecovery\":{\"sandboxId\":\"nvx:secret-123\"}} trailing")]
    [InlineData("{\"nvxRecovery\":{\"sandboxId\":\"nvx:secret-\\u003123\"}} trailing")]
    [InlineData("{\"nvxRecovery\":{\"\\u0073andboxId\":\"nvx:secret-123\"}} trailing")]
    [InlineData("{\"nvxRecovery\":{\"sandboxId\":\"nvx:secret-123")]
    public void MalformedLifecycleDetailsRedactRecoveryIdFromOriginalFailure(string detailsJson)
    {
        var detail = Detail("cleanup failed for nvx:secret-123", "Nvx.Close", "0x1234", "Retry cleanup");
        var json = Utf8(detailsJson);
        try
        {
            var ex = NativeError.ToExceptionWithDetails((int)ErrorCode.NotProvisioned, detail, "fallback", json);
            Assert.Equal(ErrorCode.BackendError, ex.Code);
            var original = Assert.IsType<MxcException>(ex.InnerException);
            Assert.Equal(ErrorCode.NotProvisioned, original.Code);
            Assert.Equal("original error message withheld because native error details were malformed", original.Message);
            Assert.Equal("Nvx.Close", original.Operation);
            Assert.Equal("0x1234", original.NativeCode);
            Assert.Equal("Retry cleanup", original.Remediation);
            Assert.Empty(ex.Data);
            Assert.Empty(original.Data);
            Assert.DoesNotContain("nvx:secret-123", ex.Message);
            Assert.DoesNotContain("nvx:secret-123", ex.ToString());
            Assert.DoesNotContain("nvx:secret-123", original.Message);
            Assert.DoesNotContain("nvx:secret-123", original.Remediation);
        }
        finally
        {
            Free(detail);
            Marshal.FreeCoTaskMem((IntPtr)json);
        }
    }

    [Theory]
    [InlineData("{\"nvxRecovery\":{\"sandboxId\":\"nvx:secret-123", "nvx:secret-123")]
    [InlineData("[]", "nvx:secret-123")]
    [InlineData("{\"nvxRecovery\":{\"sandboxId\":\"microvm:0123456789abcdef0123456789abcdef", "microvm:0123456789abcdef0123456789abcdef")]
    [InlineData("[]", "microvm:0123456789abcdef0123456789abcdef")]
    [InlineData("[]", "MICROVM:0123456789abcdef0123456789abcdef")]
    [InlineData("{\"nvxRecovery\":{\"sandboxId\":\"private-id", "private-id")]
    [InlineData("{\"nvxRecovery\":{\"\\u0073andboxId\":\"private-id\"}} trailing", "private-id")]
    [InlineData("{\"nvxRecovery\":{\"sandboxId\":\"private-\\u0069d\"}} trailing", "private-id")]
    public void MalformedLifecycleDetailsRedactRecoveryIdFromMetadata(string detailsJson, string id)
    {
        var detail = Detail($"message {id}", $"op {id}", $"code {id}", $"fix {id}");
        var json = Utf8(detailsJson);
        try
        {
            var ex = NativeError.ToExceptionWithDetails((int)ErrorCode.NotProvisioned, detail, "fallback", json);
            var original = Assert.IsType<MxcException>(ex.InnerException);
            Assert.Equal(ErrorCode.NotProvisioned, original.Code);
            Assert.DoesNotContain(id, ex.ToString());
            Assert.Null(original.Operation);
            Assert.Null(original.NativeCode);
            Assert.DoesNotContain(id, original.Remediation);
            Assert.Contains("[redacted]", original.Remediation);
        }
        finally
        {
            Free(detail);
            Marshal.FreeCoTaskMem((IntPtr)json);
        }
    }

    [Theory]
    [InlineData("op:arbitrary", "normalcode")]
    [InlineData("operation with space", "code:arbitrary")]
    [InlineData("op\targs", "code\nargs")]
    [InlineData("op\u0085args", "code\u0085args")]
    public void MalformedDetailsWithholdParameterizedOperationAndNativeCode(string operation, string nativeCode)
    {
        var detail = Detail("failure", operation, nativeCode, "safe remediation");
        var json = Utf8("[]");
        try
        {
            var ex = NativeError.ToExceptionWithDetails((int)ErrorCode.BackendError, detail, "fallback", json);
            var original = Assert.IsType<MxcException>(ex.InnerException);
            Assert.Null(original.Operation);
            if (nativeCode.Contains(':') || nativeCode.Any(char.IsWhiteSpace)) Assert.Null(original.NativeCode);
            else Assert.Equal(nativeCode, original.NativeCode);
            Assert.Equal("safe remediation", original.Remediation);
        }
        finally
        {
            Free(detail);
            Marshal.FreeCoTaskMem((IntPtr)json);
        }
    }

    [Fact]
    public void NullLifecycleDetailsLeaveTheOriginalFailureUnchanged()
    {
        var detail = Detail("original failure");
        try
        {
            var ex = NativeError.ToExceptionWithDetails((int)ErrorCode.NotProvisioned, detail, "fallback", null);
            Assert.Equal(ErrorCode.NotProvisioned, ex.Code);
            Assert.False(ex.Data.Contains("details"));
        }
        finally { Free(detail); }
    }

    [Fact]
    public void EachNativeFieldLandsOnItsOwnProperty()
    {
        var detail = Detail(
            "The provision was not found.",
            "IsoSessionOps.StopSessionAsync",
            "0x80070490",
            "Provision the session first.");

        try
        {
            var ex = NativeError.ToException(
                (int)ErrorCode.BackendError, detail, "unused fallback");

            Assert.Equal(ErrorCode.BackendError, ex.Code);
            Assert.Equal("The provision was not found.", ex.Message);
            Assert.Equal("IsoSessionOps.StopSessionAsync", ex.Operation);
            Assert.Equal("0x80070490", ex.NativeCode);
            Assert.Equal("Provision the session first.", ex.Remediation);
        }
        finally
        {
            Free(detail);
        }
    }

    [Fact]
    public void AnAbsentFieldBecomesNullAndAnEmptyOneStaysEmpty()
    {
        // The native layer uses null for "the API supplied nothing here" and
        // reserves the empty string for "it supplied an empty value". Marshalling
        // must not collapse the two, or a caller cannot tell them apart.
        var detail = Detail("boom", "Iface.Call", nativeCode: string.Empty);

        try
        {
            var ex = NativeError.ToException(
                (int)ErrorCode.BackendError, detail, "unused fallback");

            Assert.Equal("Iface.Call", ex.Operation);
            Assert.Equal(string.Empty, ex.NativeCode);
            Assert.Null(ex.Remediation);
        }
        finally
        {
            Free(detail);
        }
    }

    [Fact]
    public void AMessagelessDetailFallsBackRatherThanThrowingOrReportingNothing()
    {
        // Should not happen on a failure, but a null message must still leave
        // the caller with something actionable rather than an empty exception.
        var detail = Detail(null, "Iface.Call");

        try
        {
            var ex = NativeError.ToException(
                (int)ErrorCode.BackendError, detail, "the fallback");

            Assert.Equal("the fallback", ex.Message);
            Assert.Equal("Iface.Call", ex.Operation);
        }
        finally
        {
            Free(detail);
        }
    }

    [Fact]
    public void TheStatusCodeCrossesAsTheErrorCode()
    {
        var detail = Detail("bad json");

        try
        {
            var ex = NativeError.ToException(
                (int)ErrorCode.MalformedRequest, detail, "unused fallback");

            Assert.Equal(ErrorCode.MalformedRequest, ex.Code);
            Assert.Null(ex.Operation);
            Assert.Null(ex.NativeCode);
            Assert.Null(ex.Remediation);
        }
        finally
        {
            Free(detail);
        }
    }
}
