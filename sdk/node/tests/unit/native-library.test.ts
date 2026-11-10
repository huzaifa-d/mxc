// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { afterEach, describe, it, mock } from 'node:test';
import assert from 'node:assert';
import * as path from 'node:path';
import koffi from 'koffi';
import { _bootstrapNvxRuntimeForTest, _mxcFfiCandidates, loadMxcFfi } from '../../src/native-library.js';

const oldFfiDir = process.env.MXC_FFI_DIR;

afterEach(() => {
  if (oldFfiDir === undefined) delete process.env.MXC_FFI_DIR;
  else process.env.MXC_FFI_DIR = oldFfiDir;
});

describe('mxc_ffi library resolution', () => {
  it('uses the packaged library for each platform', () => {
    delete process.env.MXC_FFI_DIR;

    assert.strictEqual(
      _mxcFfiCandidates('sdk', 'win32', 'x64')[0],
      path.join('sdk', 'bin', 'x64', 'mxc_ffi.dll'),
    );
    assert.strictEqual(
      _mxcFfiCandidates('sdk', 'linux', 'arm64')[0],
      path.join('sdk', 'bin', 'arm64', 'libmxc_ffi.so'),
    );
    assert.strictEqual(
      _mxcFfiCandidates('sdk', 'darwin', 'arm64')[0],
      path.join('sdk', 'bin', 'arm64', 'libmxc_ffi.dylib'),
    );
  });

  it('prefers the explicit native library location', () => {
    process.env.MXC_FFI_DIR = path.join('custom', 'ffi');

    const candidates = _mxcFfiCandidates('sdk', 'win32', 'x64');
    assert.strictEqual(candidates[0], path.join('custom', 'ffi', 'mxc_ffi.dll'));
  });

  it('falls back to target-specific Cargo output', () => {
    delete process.env.MXC_FFI_DIR;

    const candidates = _mxcFfiCandidates('sdk', 'linux', 'x64');
    assert.strictEqual(
      candidates[1],
      path.join('..', 'src', 'target', 'x86_64-unknown-linux-gnu', 'release', 'libmxc_ffi.so'),
    );
  });

  it('reports every searched location when the library is missing', () => {
    const candidates = [
      path.join('custom', 'ffi', 'mxc_ffi.dll'),
      path.join('sdk', 'bin', 'x64', 'mxc_ffi.dll'),
    ];

    assert.throws(
      () => loadMxcFfi(candidates),
      (error: unknown) => error instanceof Error
        && candidates.every((candidate) => error.message.includes(candidate)),
    );
  });

  it('loads the selected library and binds mxc_version', () => {
    const libraryPath = path.resolve('package.json');

    {
      let loadedPath: string | null | undefined;
      let boundDeclaration: string | undefined;
      const version = () => 'test-version';
      const load = mock.method(koffi, 'load', (candidate: string | null) => {
        loadedPath = candidate;
        return {
          func(...args: unknown[]) {
            boundDeclaration = String(args[0]);
            return version;
          },
        };
      });

      try {
        const library = loadMxcFfi([libraryPath]);

        assert.strictEqual(loadedPath, libraryPath);
        assert.strictEqual(boundDeclaration, 'const char *mxc_version(void)');
        assert.strictEqual(library.version(), 'test-version');
      } finally {
        load.mock.restore();
      }
    }
  });
});


describe('NVX optional runtime bootstrap', () => {
  const runtimeManifest = path.join('runtime', 'package.json');
  const packageRoot = path.join('sdk');
  const directory = path.join('runtime', 'aci-edge-sandboxes');
  const canonical = path.resolve(directory);
  function dependencies(runtimeVersion = '1.2.3', sdkVersion = '1.2.3') {
    return {
      resolve: () => runtimeManifest,
      readFile: (name: string) => JSON.stringify({ version: name === runtimeManifest ? runtimeVersion : sdkVersion }),
      realpath: (name: string) => { assert.strictEqual(name, directory); return canonical; },
      isDirectory: () => true,
    };
  }
  it('ignores a missing optional runtime package', () => {
    const deps = dependencies();
    deps.resolve = () => { throw Object.assign(new Error('missing'), { code: 'MODULE_NOT_FOUND' }); };
    _bootstrapNvxRuntimeForTest({ register: () => assert.fail('unexpected registration'), freeError: () => {} }, deps, packageRoot);
  });
  it('registers the canonical runtime directory and propagates conflicting registrations', () => {
    let registered: string | undefined;
    let freed = 0;
    const native = {
      register: (backend: string, dir: string) => {
        assert.strictEqual(backend, 'microvm');
        if (registered && registered !== dir) return 11;
        registered = dir;
        return 0;
      },
      freeError: () => { freed++; },
    };
    const deps = dependencies();
    _bootstrapNvxRuntimeForTest(native, deps, packageRoot);
    _bootstrapNvxRuntimeForTest(native, deps, packageRoot);
    assert.strictEqual(registered, canonical);
    deps.realpath = () => path.resolve('other-runtime');
    assert.throws(() => _bootstrapNvxRuntimeForTest(native, deps, packageRoot), /registration failed/);
    assert.strictEqual(freed, 1);
  });
  it('rejects version mismatches, malformed manifests and missing directories', () => {
    const native = { register: () => assert.fail('unexpected registration'), freeError: () => {} };
    assert.throws(() => _bootstrapNvxRuntimeForTest(native, dependencies('2', '1'), packageRoot), /does not match/);
    const malformed = dependencies();
    malformed.readFile = () => '{';
    assert.throws(() => _bootstrapNvxRuntimeForTest(native, malformed, packageRoot), /Invalid.*installation/);
    const missing = dependencies();
    missing.realpath = () => { throw new Error('missing aci-edge-sandboxes'); };
    assert.throws(() => _bootstrapNvxRuntimeForTest(native, missing, packageRoot), /missing aci-edge-sandboxes/);
  });
});
