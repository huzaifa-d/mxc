// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { describe, it } from 'node:test';
import {
  runBindingStateAwareRequestWithNative,
  type BindingStateAwareRequest,
  type StateAwareNativeFacade,
  type StateAwareNativeResultV2,
} from '../../src/bindings/state-aware.js';
import type { AbiErrorDetail } from '../../src/bindings/native-error.js';
import { MxcError } from '../../src/v1/errors.js';

class FakeStateAwareNative implements StateAwareNativeFacade {
  readonly calls: Array<{
    request: string;
    dryRun: number;
    experimental: number;
  }> = [];
  callbackError: Error | null = null;
  nativeStatus = 0;
  resultStatus = 0;
  freeCount = 0;
  detailsJson: string | null = null;
  errorMessage: string | null = null;
  operation: string | null = null;
  nativeCode: string | null = null;
  remediation: string | null = null;

  run(
    request: string,
    dryRun: number,
    experimental: number,
    result: StateAwareNativeResultV2,
    completion: (error: Error | null, status: number) => void,
  ): void {
    this.calls.push({ request, dryRun, experimental });
    result.result.status = this.resultStatus;
    if (this.errorMessage !== null) result.result.error.message = Buffer.from(`${this.errorMessage}\0`);
    if (this.operation !== null) result.result.error.operation = Buffer.from(`${this.operation}\0`);
    if (this.nativeCode !== null) result.result.error.nativeCode = Buffer.from(`${this.nativeCode}\0`);
    if (this.remediation !== null) result.result.error.remediation = Buffer.from(`${this.remediation}\0`);
    if (this.detailsJson !== null) result.errorDetailsJsonUtf8 = Buffer.from(`${this.detailsJson}\0`);
    queueMicrotask(() => completion(this.callbackError, this.nativeStatus));
  }

  free(): void {
    this.freeCount += 1;
  }
}

const REQUEST: BindingStateAwareRequest = {
  requestJson: '{"phase":"start"}',
  dryRun: true,
  experimental: true,
};

describe('state-aware native binding ownership', () => {
  it('forwards flags and rejects a missing response while freeing the result', async () => {
    const native = new FakeStateAwareNative();

    await assert.rejects(
      () => runBindingStateAwareRequestWithNative(REQUEST, native),
      (error: unknown) => error instanceof MxcError
        && error.code === 'backend_error'
        && error.message.includes('missing JSON'),
    );
    assert.deepStrictEqual(native.calls, [{
      request: REQUEST.requestJson,
      dryRun: 1,
      experimental: 1,
    }]);
    assert.strictEqual(native.freeCount, 1);
  });

  it('frees a populated result when native status decoding fails', async () => {
    const native = new FakeStateAwareNative();
    native.nativeStatus = 12;

    await assert.rejects(
      () => runBindingStateAwareRequestWithNative(REQUEST, native),
      (error: unknown) =>
        error instanceof MxcError &&
        error.code === 'backend_error',
    );
    assert.strictEqual(native.freeCount, 1);
  });

  it('frees a populated result when the result reports failure', async () => {
    const native = new FakeStateAwareNative();
    native.resultStatus = 12;

    await assert.rejects(
      () => runBindingStateAwareRequestWithNative(REQUEST, native),
      (error: unknown) =>
        error instanceof MxcError &&
        error.code === 'backend_error',
    );
    assert.strictEqual(native.freeCount, 1);
  });

  it('does not free a result when the asynchronous call itself fails', async () => {
    const native = new FakeStateAwareNative();
    native.callbackError = new Error('callback failed');

    await assert.rejects(
      () => runBindingStateAwareRequestWithNative(REQUEST, native),
      /callback failed/,
    );
    assert.strictEqual(native.freeCount, 0);
  });
  it('copies recovery details before free without exposing the id in the message', async () => {
    const native = new FakeStateAwareNative();
    native.resultStatus = 12;
    native.errorMessage = 'cleanup failed for private-id';
    native.operation = 'operation private-id';
    native.nativeCode = 'code private-id';
    native.remediation = 'fix private-id';
    native.detailsJson = JSON.stringify({ nvxRecovery: { sandboxId: 'private-id', state: 'provisioned' }, ffiStatus: 99 });
    await assert.rejects(() => runBindingStateAwareRequestWithNative(REQUEST, native), (error: unknown) => {
      assert.ok(error instanceof MxcError);
      assert.deepStrictEqual(error.details?.nvxRecovery, { sandboxId: 'private-id', state: 'provisioned' });
      assert.strictEqual(error.details?.ffiStatus, 12);
      assert.ok(!error.message.includes('private-id'));
      assert.ok(!String(error).includes('private-id'));
      assert.ok(!error.operation?.includes('private-id'));
      assert.ok(!error.nativeCode?.includes('private-id'));
      assert.ok(!error.remediation?.includes('private-id'));
      return true;
    });
    assert.strictEqual(native.freeCount, 1);
  });

  for (const detailsJson of [
    '{"nvxRecovery":{"sandboxId":"nvx:secret-123"}} trailing',
    '{"nvxRecovery":{"sandboxId":"nvx:secret-\\u003123"}} trailing',
    '{"nvxRecovery":{"\\u0073andboxId":"nvx:secret-123"}} trailing',
    '{"nvxRecovery":{"sandboxId":"nvx:secret-123',
  ]) {
    it('redacts the recovery ID from a preserved cause when details are malformed', async () => {
      const native = new FakeStateAwareNative();
      native.resultStatus = 7;
      native.errorMessage = 'cleanup failed for nvx:secret-123';
      native.operation = 'Nvx.Close';
      native.nativeCode = '0x1234';
      native.remediation = 'Retry cleanup';
      native.detailsJson = detailsJson;
      await assert.rejects(() => runBindingStateAwareRequestWithNative(REQUEST, native), (error: unknown) => {
        assert.ok(error instanceof MxcError);
        assert.strictEqual(error.code, 'backend_error');
        const cause = error.details?.cause;
        assert.ok(cause instanceof MxcError);
        assert.strictEqual(cause.code, 'not_provisioned');
        assert.strictEqual(cause.message, 'original error message withheld because native error details were malformed');
        assert.strictEqual(cause.operation, 'Nvx.Close');
        assert.strictEqual(cause.nativeCode, '0x1234');
        assert.strictEqual(cause.remediation, 'Retry cleanup');
        assert.strictEqual(error.details?.ffiStatus, 7);
        assert.strictEqual(cause.details?.ffiStatus, 7);
        assert.ok(!JSON.stringify(error.details).includes('nvx:secret-123'));
        assert.ok(!error.message.includes('nvx:secret-123'));
        assert.ok(!String(error).includes('nvx:secret-123'));
        assert.ok(!cause.message.includes('nvx:secret-123'));
        assert.ok(!String(cause).includes('nvx:secret-123'));
        return true;
      });
      assert.strictEqual(native.freeCount, 1);
    });
  }

  for (const [detailsJson, id] of [
    ['{"nvxRecovery":{"sandboxId":"nvx:secret-123', 'nvx:secret-123'],
    ['[]', 'nvx:secret-123'],
    ['{"nvxRecovery":{"sandboxId":"microvm:0123456789abcdef0123456789abcdef', 'microvm:0123456789abcdef0123456789abcdef'],
    ['[]', 'microvm:0123456789abcdef0123456789abcdef'],
    ['[]', 'MICROVM:0123456789abcdef0123456789abcdef'],
    ['{"nvxRecovery":{"sandboxId":"private-id', 'private-id'],
    ['{"nvxRecovery":{"\\u0073andboxId":"private-id"}} trailing', 'private-id'],
    ['{"nvxRecovery":{"sandboxId":"private-\\u0069d"}} trailing', 'private-id'],
  ]) {
    it('redacts recovery IDs from malformed-details metadata', async () => {
      const native = new FakeStateAwareNative();
      native.resultStatus = 7;
      native.errorMessage = `message ${id}`;
      native.operation = `op ${id}`;
      native.nativeCode = `code ${id}`;
      native.remediation = `fix ${id}`;
      native.detailsJson = detailsJson;
      await assert.rejects(() => runBindingStateAwareRequestWithNative(REQUEST, native), (error: unknown) => {
        assert.ok(error instanceof MxcError);
        const cause = error.details?.cause;
        assert.ok(cause instanceof MxcError);
        assert.strictEqual(cause.code, 'not_provisioned');
        assert.strictEqual(error.details?.ffiStatus, 7);
        assert.ok(!JSON.stringify(error.details).includes(id));
        assert.ok(!String(cause).includes(id));
        assert.strictEqual(cause.operation, undefined);
        assert.strictEqual(cause.nativeCode, undefined);
        assert.strictEqual(cause.remediation, 'fix [redacted]');
        return true;
      });
      assert.strictEqual(native.freeCount, 1);
    });
  }

  for (const [operation, nativeCode, expectedCode] of [
    ['op:arbitrary', 'normalcode', 'normalcode'],
    ['operation with space', 'code:arbitrary', undefined],
    ['op\targs', 'code\nargs', undefined],
    ['op\u0085args', 'code\u0085args', undefined],
  ] as const) {
    it('withholds parameterized operation and native code for malformed details', async () => {
      const native = new FakeStateAwareNative();
      native.resultStatus = 12;
      native.operation = operation;
      native.nativeCode = nativeCode;
      native.remediation = 'safe remediation';
      native.detailsJson = '[]';
      await assert.rejects(() => runBindingStateAwareRequestWithNative(REQUEST, native), (error: unknown) => {
        assert.ok(error instanceof MxcError);
        const cause = error.details?.cause;
        assert.ok(cause instanceof MxcError);
        assert.strictEqual(cause.operation, undefined);
        assert.strictEqual(cause.nativeCode, expectedCode);
        assert.strictEqual(cause.remediation, 'safe remediation');
        return true;
      });
    });
  }

  for (const json of ['{', '[]', 'null']) {
    it(`rejects invalid error details ${json} and preserves the original error`, async () => {
      const native = new FakeStateAwareNative();
      native.resultStatus = 7;
      native.detailsJson = json;
      await assert.rejects(() => runBindingStateAwareRequestWithNative(REQUEST, native), (error: unknown) => {
        assert.ok(error instanceof MxcError);
        assert.strictEqual(error.code, 'backend_error');
        assert.ok(error.details?.cause instanceof MxcError);
        assert.strictEqual((error.details.cause as MxcError).code, 'not_provisioned');
        assert.strictEqual(error.details?.ffiStatus, 7);
        return true;
      });
      assert.strictEqual(native.freeCount, 1);
    });
  }

});
