// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { afterEach, describe, it, mock } from 'node:test';
import assert from 'node:assert';
import * as path from 'node:path';
import * as fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { AbiErrorDetailType, type AbiErrorDetail } from '../../src/bindings/native-error.js';
import { runBindingStateAwareRequestAsync } from '../../src/bindings/state-aware.js';
import { MxcError } from '../../src/v1/errors.js';
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

it('calls registration and lifecycle v2 through a real Windows DLL', {
  skip: process.platform !== 'win32' || process.arch !== 'x64' ||
    !_mxcFfiCandidates().some(candidate => fs.existsSync(candidate)),
}, async () => {
  const library = loadMxcFfi();
  const register = library.handle.func('mxc_register_runtime_directory', 'int32_t', [
    'const char *', 'const char *', koffi.out(koffi.pointer(AbiErrorDetailType)),
  ]);
  const free = library.handle.func('mxc_error_detail_free', 'void', [koffi.pointer(AbiErrorDetailType)]);
  const error = {} as AbiErrorDetail;
  try {
    assert.notStrictEqual(register('unsupported-backend', process.cwd(), error), 0);
  } finally {
    free(error);
    library.handle.unload();
  }
  await assert.rejects(runBindingStateAwareRequestAsync({
    requestJson: '{"version":"1.0.0","phase":"start","sandboxId":"nosuchbackend:abc123"}',
    dryRun: true, experimental: true,
  }), (error: unknown) => error instanceof MxcError && error.code === 'unsupported_containment');
});

const packagedTestCandidates = process.platform === 'win32' && process.arch === 'x64'
  ? (process.env.MXC_NVX_TEST_DLL ? [path.resolve(process.env.MXC_NVX_TEST_DLL)] : _mxcFfiCandidates())
  : [];
const packagedTestLibrary = packagedTestCandidates.find(candidate => fs.existsSync(candidate)
  && fs.existsSync(path.join(path.dirname(candidate), 'aci-edge-sandboxes', 'bundle-manifest.json')));

it('discovers the installed NVX package through the real native DLL without overrides', {
  skip: process.platform !== 'win32' || process.arch !== 'x64' ||
    (!packagedTestLibrary && !process.env.MXC_NVX_TEST_DLL),
}, (t) => {
  assert.ok(packagedTestLibrary, 'the selected NVX test DLL and runtime bundle must exist');
  const sdkRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
  const library = packagedTestLibrary;
  const fixture = fs.mkdtempSync(path.join(sdkRoot, '.nvx-packaged-discovery-'));
  try {
    fs.writeFileSync(path.join(fixture, 'package.json'), JSON.stringify({ private: true, type: 'module' }));
    const modules = path.join(fixture, 'node_modules', '@microsoft');
    const sdk = path.join(modules, 'mxc-sdk');
    const runtime = path.join(modules, 'mxc-sdk-nvx-runtime-win32-x64');
    fs.mkdirSync(path.join(sdk, 'bin', 'x64'), { recursive: true });
    fs.mkdirSync(runtime, { recursive: true });
    fs.cpSync(path.join(sdkRoot, 'dist-tests', 'src'), path.join(sdk, 'dist'), { recursive: true });
    fs.copyFileSync(path.join(sdkRoot, 'package.json'), path.join(sdk, 'package.json'));
    fs.copyFileSync(library, path.join(sdk, 'bin', 'x64', 'mxc_ffi.dll'));
    fs.copyFileSync(path.join(sdkRoot, '..', 'node-nvx-runtime', 'package.json'), path.join(runtime, 'package.json'));
    fs.cpSync(path.join(path.dirname(library), 'aci-edge-sandboxes'), path.join(runtime, 'aci-edge-sandboxes'), { recursive: true });
    const script = `
      import assert from 'node:assert/strict';
      import path from 'node:path';
      import fs from 'node:fs';
      import { createRequire } from 'node:module';
      import koffi from 'koffi';
      import { getPlatformSupport, getAvailableBackends } from '@microsoft/mxc-sdk/v1';
      assert.ok(!process.env.MXC_FFI_DIR && !process.env.ACI_EDGE_SANDBOXES_AGENT_ARTIFACTS_DIR);
      const require = createRequire(import.meta.url);
      for (const name of ['mxc-sdk', 'mxc-sdk-nvx-runtime-win32-x64']) {
        assert.equal(fs.realpathSync(require.resolve('@microsoft/' + name + '/package.json')),
          fs.realpathSync(path.resolve('node_modules/@microsoft', name, 'package.json')));
      }
      assert.equal(typeof getPlatformSupport().isSupported, 'boolean');
      assert.ok(Array.isArray(getAvailableBackends()));
      const native = koffi.load(path.resolve('node_modules/@microsoft/mxc-sdk/bin/x64/mxc_ffi.dll'));
      const detailType = koffi.struct('NvxPackageSmokeError', {
        message: 'void *', operation: 'void *', nativeCode: 'void *', remediation: 'void *',
      });
      const register = native.func('mxc_register_runtime_directory', 'int32_t',
        ['const char *', 'const char *', koffi.out(koffi.pointer(detailType))]);
      const free = native.func('mxc_error_detail_free', 'void', [koffi.pointer(detailType)]);
      const detail = {};
      try { assert.equal(register('microvm', process.cwd(), detail), 11); }
      finally { free(detail); native.unload(); }
    `;
    const env: NodeJS.ProcessEnv = { ...process.env, MXC_FFI_DIR: '', ACI_EDGE_SANDBOXES_AGENT_ARTIFACTS_DIR: '' };
    delete env.MXC_NVX_TEST_DLL;
    const child = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
      cwd: fixture, env, encoding: 'utf8', timeout: 60_000,
    });
    assert.ifError(child.error);
    if (!process.env.MXC_NVX_TEST_DLL && child.status !== 0 &&
      child.stderr.includes('MicroVM runtime is unavailable on this platform')) {
      t.skip('the discovered native DLL was built without MicroVM');
      return;
    }
    assert.strictEqual(child.status, 0, child.stdout + child.stderr);
  } finally {
    fs.rmSync(fixture, { recursive: true, force: true });
  }
});
