// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Async native binding for state-aware lifecycle phases that run to completion.

import koffi from 'koffi';
import { MxcError } from '../v1/errors.js';
import { loadMxcFfi } from '../native-library.js';
import { bindNativeFunction } from './native-function.js';
import {
  AbiErrorDetailType,
  decodeString,
  nativeStatusError,
  type AbiErrorDetail,
} from './native-error.js';

export interface StateAwareNativeResult {
  status: number;
  responseJsonUtf8: unknown | null;
  error: AbiErrorDetail;
}

export interface StateAwareNativeResultV2 {
  result: StateAwareNativeResult;
  errorDetailsJsonUtf8: unknown | null;
}

export interface BindingStateAwareRequest {
  requestJson: string;
  dryRun: boolean;
  experimental: boolean;
}

const AbiStateAwareResultType = koffi.struct('MxcNodeStateAwareResult', {
  status: 'int32_t',
  responseJsonUtf8: 'void *',
  error: AbiErrorDetailType,
});

const AbiStateAwareResultV2Type = koffi.struct('MxcNodeStateAwareResultV2', {
  result: AbiStateAwareResultType,
  errorDetailsJsonUtf8: 'void *',
});

type StateAwareFunction = (
  request: string,
  dryRun: number,
  experimental: number,
  result: StateAwareNativeResultV2,
) => number;
type FreeFunction = (result: StateAwareNativeResultV2) => void;
type StateAwareCompletion = (error: Error | null, status: number) => void;

export interface StateAwareNativeFacade {
  run(
    request: string,
    dryRun: number,
    experimental: number,
    result: StateAwareNativeResultV2,
    completion: StateAwareCompletion,
  ): void;
  free(result: StateAwareNativeResultV2): void;
}

function bindStateAwareNativeFacade(
  native: ReturnType<typeof loadMxcFfi>,
): StateAwareNativeFacade {
  const run = bindNativeFunction<StateAwareFunction>(native.handle, {
    symbol: 'mxc_run_state_aware_json_v2',
    result: 'int32_t',
    parameters: [
      'const char *',
      'int32_t',
      'int32_t',
      koffi.out(koffi.pointer(AbiStateAwareResultV2Type)),
    ],
  });
  const free = bindNativeFunction<FreeFunction>(native.handle, {
    symbol: 'mxc_state_aware_result_v2_free',
    result: 'void',
    parameters: [koffi.pointer(AbiStateAwareResultV2Type)],
  });
  return {
    run(request, dryRun, experimental, result, completion) {
      run.async(request, dryRun, experimental, result, completion);
    },
    free,
  };
}

function createStateAwareResult(): StateAwareNativeResultV2 {
  return {
    errorDetailsJsonUtf8: null,
    result: {
      status: 0,
      responseJsonUtf8: null,
      error: {
        message: null,
        operation: null,
        nativeCode: null,
        remediation: null,
      },
    },
  };
}

function malformedDetailsRedactor(detailsJson: string): (value: string | undefined) => string | undefined {
  const ids: string[] = [];
  for (const match of detailsJson.matchAll(/("(?:\\.|[^"\\])*")\s*:\s*("(?:\\.|[^"\\])*(?:(")|$))/g)) {
    try {
      const key: unknown = JSON.parse(match[1]);
      const rawValue = match[3] === undefined ? `${match[2]}"` : match[2];
      const id: unknown = JSON.parse(rawValue);
      if (key === 'sandboxId' && typeof id === 'string' && id.length > 0) ids.push(id);
    } catch {
      // The surrounding JSON is already known to be invalid.
    }
  }
  return (value) => {
    if (value === undefined) return undefined;
    for (const id of ids) value = value.split(id).join('[redacted]');
    return value.replace(/(?:microvm|nvx):[^\s\]"'`,;]+/gi, '[redacted]');
  };
}

function decodeStateAwareResult(
  nativeStatus: number,
  outer: StateAwareNativeResultV2,
): string {
  const result = outer.result;
  if (nativeStatus !== 0 || result.status !== 0) {
    const original = nativeStatusError(
      result.status || nativeStatus,
      result.error,
      'state-aware request failed',
    );
    const detailsJson = decodeString(outer.errorDetailsJsonUtf8);
    if (detailsJson === undefined) throw original;
    let details: unknown;
    try {
      details = JSON.parse(detailsJson);
      if (details === null || typeof details !== 'object' || Array.isArray(details)) {
        throw new Error('details are not an object');
      }
    } catch {
      const redact = malformedDetailsRedactor(detailsJson);
      const parameterFree = (value: string | undefined): string | undefined => {
        const redacted = redact(value);
        return redacted !== undefined && /[:\s\p{White_Space}]/u.test(redacted) ? undefined : redacted;
      };
      const cause = new MxcError({
        code: original.code,
        message: 'original error message withheld because native error details were malformed',
        operation: parameterFree(original.operation),
        nativeCode: parameterFree(original.nativeCode),
        remediation: redact(original.remediation),
        details: { ffiStatus: result.status || nativeStatus },
      });
      throw new MxcError({
        code: 'backend_error',
        message: 'native lifecycle returned malformed error details',
        details: { cause, ffiStatus: result.status || nativeStatus },
      });
    }
    const detailObject = details as Record<string, unknown>;
    const recovery = detailObject.nvxRecovery;
    const sandboxId = recovery !== null && typeof recovery === 'object' && !Array.isArray(recovery)
      ? (recovery as Record<string, unknown>).sandboxId : undefined;
    const redact = (value: string | undefined): string | undefined =>
      typeof sandboxId === 'string' && sandboxId.length > 0 && value !== undefined
        ? value.split(sandboxId).join('[redacted]') : value;
    throw new MxcError({
      code: original.code,
      message: redact(original.message)!,
      operation: redact(original.operation),
      nativeCode: redact(original.nativeCode),
      remediation: redact(original.remediation),
      details: { ...detailObject, ffiStatus: result.status || nativeStatus },
    });
  }
  const responseJson = decodeString(result.responseJsonUtf8);
  if (responseJson === undefined || responseJson.length === 0) {
    throw new MxcError('backend_error', 'native lifecycle response is missing JSON');
  }
  return responseJson;
}

export async function runBindingStateAwareRequestWithNative(
  request: BindingStateAwareRequest,
  native: StateAwareNativeFacade,
): Promise<string> {
  const result = createStateAwareResult();
  let ownsResult = false;
  try {
    const nativeStatus = await new Promise<number>((resolve, reject) => {
      native.run(
        request.requestJson,
        request.dryRun ? 1 : 0,
        request.experimental ? 1 : 0,
        result,
        (error, status) => {
          if (error !== null) {
            reject(error);
            return;
          }
          ownsResult = true;
          resolve(status);
        },
      );
    });
    return decodeStateAwareResult(nativeStatus, result);
  } finally {
    if (ownsResult) native.free(result);
  }
}

async function runBindingStateAwareRequestAsyncNative(
  request: BindingStateAwareRequest,
): Promise<string> {
  const native = loadMxcFfi();
  try {
    return await runBindingStateAwareRequestWithNative(
      request,
      bindStateAwareNativeFacade(native),
    );
  } finally {
    native.handle.unload();
  }
}

type AsyncStateAwareImplementation = (
  request: BindingStateAwareRequest,
) => Promise<string>;

let asyncStateAwareImplementation = runBindingStateAwareRequestAsyncNative;

/** @internal Replaces the async native call for one process's unit tests. */
export function _setBindingStateAwareAsyncImplementation(
  implementation?: AsyncStateAwareImplementation,
): void {
  asyncStateAwareImplementation =
    implementation ?? runBindingStateAwareRequestAsyncNative;
}

export function runBindingStateAwareRequestAsync(
  request: BindingStateAwareRequest,
): Promise<string> {
  return asyncStateAwareImplementation(request).catch((error: unknown) => {
    if (error instanceof MxcError) throw error;
    throw new MxcError(
      'backend_error',
      error instanceof Error ? error.message : String(error),
    );
  });
}
