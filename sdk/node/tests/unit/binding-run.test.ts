// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from 'node:assert';
import { describe, it } from 'node:test';
import { _errorCodeForNativeStatus } from '../../src/bindings/run.js';
import { nativeStatusError } from '../../src/bindings/native-error.js';

describe('native run binding', () => {
  it('preserves creation-policy text after native message storage is released', () => {
    const message = [
      'CreateProcessSecurityEnvironment failed (HRESULT = 0x800704EC)',
      'Returned constraints: 2 (non-exhaustive).',
      'Resource 1: "C:\\\\work"',
      'Resource 2: "C:\\\\\u65e5\u672c"',
      'required=18446744073709551615.',
    ].join('\n');
    const storage = Buffer.from(`${message}\0`, 'utf8');
    const error = nativeStatusError(12, { message: storage });
    storage.fill(0);
    assert.strictEqual(error.code, 'backend_error');
    assert.strictEqual(error.message, message);
    assert.deepStrictEqual(error.details, { ffiStatus: 12 });
    assert.strictEqual(error.operation, undefined);
    assert.strictEqual(error.nativeCode, undefined);
  });

  it('maps SDK status codes', () => {
    assert.strictEqual(_errorCodeForNativeStatus(1), 'malformed_request');
    assert.strictEqual(_errorCodeForNativeStatus(2), 'unsupported_containment');
    assert.strictEqual(_errorCodeForNativeStatus(4), 'backend_unavailable');
    assert.strictEqual(_errorCodeForNativeStatus(11), 'policy_validation');
    assert.strictEqual(_errorCodeForNativeStatus(12), 'backend_error');
  });

  it('maps FFI contract failures without inventing new public codes', () => {
    assert.strictEqual(_errorCodeForNativeStatus(100), 'malformed_request');
    assert.strictEqual(_errorCodeForNativeStatus(101), 'malformed_request');
    assert.strictEqual(_errorCodeForNativeStatus(102), 'backend_error');
    assert.strictEqual(_errorCodeForNativeStatus(103), 'backend_error');
    assert.strictEqual(_errorCodeForNativeStatus(999), 'backend_error');
  });
});
