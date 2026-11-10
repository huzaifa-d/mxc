// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Runtime.InteropServices;
using System.Text.Json;

using Microsoft.Mxc.Sdk.V1;

namespace Microsoft.Mxc.Sdk.Native;

/// <summary>
/// Turns the native failure detail into an <see cref="MxcException"/>.
/// </summary>
/// <remarks>
/// Shared rather than repeated per call site so every entry point reports a
/// failure the same way. Each field is carried across independently: an
/// operation with no status is a supported and tested shape, so this preserves
/// whatever the native layer supplied per field rather than treating the three
/// as a unit. Absence stays distinguishable from the empty string.
/// </remarks>
internal static unsafe class NativeError
{
    /// <summary>
    /// Build an exception from a native detail.
    /// </summary>
    /// <param name="status">The native status code.</param>
    /// <param name="detail">The detail the native layer filled.</param>
    /// <param name="fallbackMessage">
    /// Used when the native layer supplied no message — which should not happen
    /// on a failure, but leaves the caller with something actionable if it does.
    /// </param>
    internal static MxcException ToException(
        int status,
        MxcErrorDetail detail,
        string fallbackMessage)
    {
        return new MxcException(
            (ErrorCode)status,
            ToStringOrNull(detail.message_utf8) ?? fallbackMessage,
            ToStringOrNull(detail.operation_utf8),
            ToStringOrNull(detail.native_code_utf8),
            ToStringOrNull(detail.remediation_utf8));
    }

    internal static MxcException ToExceptionWithDetails(
        int status, MxcErrorDetail detail, string fallbackMessage, byte* detailsJsonUtf8)
    {
        var original = ToException(status, detail, fallbackMessage);
        if (detailsJsonUtf8 is null)
        {
            return original;
        }

        try
        {
            var details = MxcJson.Deserialize<JsonElement>(ToStringOrNull(detailsJsonUtf8)!);
            if (details.ValueKind != JsonValueKind.Object)
            {
                throw new JsonException("Lifecycle error details must be an object.");
            }
            if (details.TryGetProperty("nvxRecovery", out var recovery)
                && recovery.ValueKind == JsonValueKind.Object
                && recovery.TryGetProperty("sandboxId", out var idElement)
                && idElement.ValueKind == JsonValueKind.String
                && idElement.GetString() is { Length: > 0 } id)
            {
                static string? Redact(string? value, string id) =>
                    value?.Replace(id, "[redacted]", StringComparison.Ordinal);
                original = new MxcException(original.Code, Redact(original.Message, id)!,
                    Redact(original.Operation, id), Redact(original.NativeCode, id),
                    Redact(original.Remediation, id));
            }
            original.Data["details"] = details.Clone();
            return original;
        }
        catch (JsonException)
        {
            return new MxcException(ErrorCode.BackendError,
                "native lifecycle returned malformed error details", original);
        }
    }

    /// <summary>
    /// Marshal a native UTF-8 string, mapping a null pointer to
    /// <see langword="null"/> rather than to the empty string — the native layer
    /// uses null to mean "the API supplied nothing here".
    /// </summary>
    internal static string? ToStringOrNull(byte* p) =>
        p is null ? null : Marshal.PtrToStringUTF8((IntPtr)p);
}
