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
    native.detailsJson = JSON.stringify({ nvxRecovery: { sandboxId: 'private-id', state: 'provisioned' }, ffiStatus: 99 });
    await assert.rejects(() => runBindingStateAwareRequestWithNative(REQUEST, native), (error: unknown) => {
      assert.ok(error instanceof MxcError);
      assert.deepStrictEqual(error.details?.nvxRecovery, { sandboxId: 'private-id', state: 'provisioned' });
      assert.strictEqual(error.details?.ffiStatus, 12);
      assert.ok(!error.message.includes('private-id'));
      assert.ok(!String(error).includes('private-id'));
      return true;
    });
    assert.strictEqual(native.freeCount, 1);
  });

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
