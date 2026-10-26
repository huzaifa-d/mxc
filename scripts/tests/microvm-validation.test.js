// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const { after, before, test } = require("node:test");
const assert = require("node:assert/strict");
const {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} = require("node:fs");
const { tmpdir } = require("node:os");
const { delimiter, join, resolve } = require("node:path");
const { spawnSync } = require("node:child_process");
const { pathToFileURL } = require("node:url");
const { stripVTControlCharacters } = require("node:util");

const root = resolve(__dirname, "..", "..");
const dispatcher = join(root, "scripts", "ci", "run_backend_validation_tests.ps1");
const staging = join(root, "scripts", "ci", "stage-nvx-validation-tests.ps1");
const packaging = join(root, "scripts", "ci", "Invoke-CratePackage.ps1");
const microvmFixtures = [
  "microvm_hello.json",
  "microvm_exit_code.json",
  "microvm_multiline.json",
  "microvm_stdlib.json",
  "microvm_large_output.json",
  "microvm_error.json",
  "microvm_timeout.json",
];
let scratch;
let fixture;
let tools;

function runScript(script, args, env) {
  const result = spawnSync(
    "pwsh",
    ["-NoProfile", "-File", script, ...args],
    {
      cwd: root,
      env: { ...process.env, ...env },
      encoding: "utf8",
      timeout: 30_000,
    }
  );
  assert.ifError(result.error);
  return {
    status: result.status,
    output: stripVTControlCharacters(result.stdout + result.stderr),
  };
}

before(() => {
  scratch = mkdtempSync(join(tmpdir(), "mxc-microvm-validation-"));
  tools = join(scratch, "tools");
  mkdirSync(tools);
  fixture = join(scratch, "fixture.exe");
  const source = join(scratch, "fixture.rs");
  // A native fixture exercises the real dispatcher's process and exit handling.
  writeFileSync(source, String.raw`
use std::{env, path::Path, process};

fn main() {
    let args: Vec<_> = env::args().skip(1).collect();
    let mode = env::var("MXC_CI_FIXTURE_MODE").unwrap_or_default();
    let exe = env::current_exe().unwrap();
    if exe.file_stem().unwrap() == "cargo" {
        if args.first().map(String::as_str) == Some("metadata") {
            let target = env::var("MXC_CI_PACKAGE_TARGET").unwrap();
            let manifest = env::var("MXC_CI_PACKAGE_MANIFEST").unwrap();
            println!(r#"{{"packages":[{{"name":"mxc-sdk","version":"1.0.0","manifest_path":{manifest:?},"description":"fixture","repository":"https://github.com/microsoft/mxc","license":"MIT","dependencies":[]}}],"target_directory":{target:?}}}"#);
            return;
        }
        if args.first().map(String::as_str) == Some("fetch") {
            return;
        }
        if args.first().map(String::as_str) == Some("package") {
            assert!(args.contains(&"--no-verify".to_owned()));
            let directory = Path::new(&env::var("MXC_CI_PACKAGE_TARGET").unwrap()).join("package");
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::copy(env::var("MXC_CI_PACKAGE_ARCHIVE").unwrap(), directory.join("mxc-sdk-1.0.0.crate")).unwrap();
            return;
        }
        assert!(args.contains(&"--locked".to_owned()));
        assert!(args.contains(&"--release".to_owned()));
        assert!(args.contains(&"--no-run".to_owned()));
        assert!(args.windows(2).any(|pair| pair == ["--test", "nvx_e2e"]));
        assert!(args.windows(2).any(|pair| pair == ["--target", "x86_64-pc-windows-msvc"]));
        if let Some(index) = args.iter().position(|arg| arg == "--manifest-path") {
            let manifest = Path::new(&args[index + 1]);
            assert!(manifest.is_file());
            assert_eq!(manifest.parent().unwrap().file_name().unwrap(), "mxc-sdk-1.0.0");
            assert!(args.contains(&"--offline".to_owned()));
            if mode == "packaged-build-failure" {
                eprintln!("fixture packaged compilation failed");
                process::exit(29);
            }
            println!("PACKAGE_COMPILED extracted nvx_e2e target");
            return;
        }
        if mode == "cargo-failure" {
            eprintln!("fixture cargo failed");
            process::exit(17);
        }
        if mode != "cargo-no-artifact" {
            let executable = env::var("MXC_CI_FIXTURE_EXECUTABLE").unwrap();
            assert!(Path::new(&executable).is_file());
            println!("{{\"reason\":\"compiler-artifact\",\"target\":{{\"name\":\"nvx_e2e\"}},\"profile\":{{\"test\":true}},\"executable\":{executable:?}}}");
        }
        return;
    }
    if args == ["--list"] {
        println!("windows_x64::host_only_executor_request_matrix: test");
        println!("windows_x64::signed_bundle_executor_configs: test");
        println!("windows_x64::signed_bundle_executor_create_and_run: test");
        if mode != "missing-interruption-discovery" {
            println!("windows_x64::signed_bundle_executor_console_interrupt: test");
        }
        if mode != "missing-discovery" {
            println!("windows_x64::signed_bundle_facade_create_and_run: test");
        }
        return;
    }
    assert!(args.contains(&"--include-ignored".to_owned()));
    assert!(args.contains(&"--nocapture".to_owned()));
    assert!(args.contains(&"--test-threads=1".to_owned()));
    if mode == "native-failure" {
        eprintln!("fixture runtime failed");
        process::exit(23);
    }
    if mode == "zero-tests" {
        println!("test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;");
        return;
    }
    if mode != "missing-facade" {
        println!("VM_EXECUTED facade sequential stdout/stderr/exit/env/cwd/timeout/capture-limit/cleanup");
    }
    if mode != "missing-executor" {
        println!("VM_EXECUTED executor sequential stdout/stderr/exit/timeout/capture-limit/cleanup");
    }
    if mode != "missing-configs" {
        println!("VM_EXECUTED executor configs all seven fixtures");
    }
    if mode != "missing-interruption" {
        println!("VM_EXECUTED executor console interruption startup/execution/owned-vmm/cleanup");
    }
    if mode == "skipped" {
        println!("SKIPPED: fixture VM unavailable");
    }
    let ignored = if mode == "ignored" { 1 } else { 0 };
    println!("test result: ok. 7 passed; 0 failed; {ignored} ignored; 0 measured; 0 filtered out;");
}
`);
  const build = spawnSync(
    "rustc",
    ["--edition=2021", "--crate-name", "mxc_ci_fixture", source, "-o", fixture],
    { cwd: root, encoding: "utf8", timeout: 60_000 }
  );
  assert.ifError(build.error);
  assert.equal(build.status, 0, build.stdout + build.stderr);
  copyFileSync(fixture, join(tools, "cargo.exe"));
});

after(() => {
  if (scratch) rmSync(scratch, { recursive: true, force: true });
});

function artifact() {
  const directory = mkdtempSync(join(scratch, "artifact-"));
  copyFileSync(fixture, join(directory, "wxc-exec.exe"));
  copyFileSync(fixture, join(directory, "nvx-e2e-tests.exe"));
  mkdirSync(join(directory, "aci-edge-sandboxes"));
  writeFileSync(
    join(directory, "aci-edge-sandboxes", "bundle-manifest.json"),
    "{}"
  );
  return directory;
}

function dispatch(directory, mode = "", architecture = "x64") {
  return runScript(
    dispatcher,
    [
      "-Backend", "microvm", "-BinaryDirectory", directory, "-Architecture", architecture,
      "-TempDirectory", join(directory, "logs"),
    ],
    {
      MXC_CI_FIXTURE_MODE: mode,
    }
  );
}

test("nightly schedules exactly Windows 25H2 x64 MicroVM", async () => {
  const { expandPlan, readCatalog } = await import(
    pathToFileURL(join(root, "scripts", "ci", "resolve-validation-test-matrix.mjs"))
  );
  const catalog = readCatalog(join(root, "scripts", "ci", "validation-test-matrix.json"));
  assert.deepEqual(
    expandPlan(catalog, "nightly")
      .filter((entry) => entry.backend === "microvm")
      .map(({ os, architecture, target, artifact }) => ({ os, architecture, target, artifact })),
    [{
      os: "windows-25h2",
      architecture: "x64",
      target: "x86_64-pc-windows-msvc",
      artifact: "wxc-binaries-x86_64-pc-windows-msvc",
    }]
  );
});

test("Windows builds stage and upload the SDK tests and the complete runtime bundle", () => {
  const workflow = readFileSync(join(root, ".github", "workflows", "Build.Windows.Job.yml"), "utf8");
  assert.match(workflow, /node --test scripts\/tests\/microvm-validation\.test\.js/);
  assert.match(workflow, /scripts\/ci\/stage-nvx-validation-tests\.ps1/);
  assert.ok(workflow.includes("src/target/${{ matrix.target }}/release/nvx-e2e-tests.exe"));
  assert.ok(workflow.includes("src/target/${{ matrix.target }}/release/aci-edge-sandboxes/"));
  assert.match(workflow, /Invoke-CratePackage\.ps1[\s\S]*-VerifyMicrovmTests/);
  assert.match(workflow, /ACI_EDGE_SANDBOXES_AGENT_BUNDLE_DIR:/);
  assert.equal(existsSync(join(root, ".github", "workflows", "microvm-e2e.yml")), false);
});

test("MicroVM fixtures are canonical packaged inputs and remain in schema validation", () => {
  const fixtureRoot = join(root, "src", "mxc-sdk", "tests", "fixtures", "microvm");
  const sdkTests = readFileSync(join(root, "src", "mxc-sdk", "tests", "nvx_e2e.rs"), "utf8");
  for (const name of microvmFixtures) {
    const request = JSON.parse(readFileSync(join(fixtureRoot, name), "utf8"));
    assert.equal(request.version, "1.1.0-alpha");
    assert.equal(request.containment, "microvm");
    assert.equal(existsSync(join(root, "tests", "configs", name)), false);
    assert.ok(sdkTests.includes(`include_str!("fixtures/microvm/${name}")`), name);
  }
  const validation = readFileSync(join(root, "scripts", "versioning", "validate-configs.js"), "utf8");
  assert.ok(validation.includes('join("src", "mxc-sdk", "tests", "fixtures", "microvm")'));
});

function verifyPackage(mode = "") {
  const directory = mkdtempSync(join(scratch, "package-"));
  const inputs = join(directory, "inputs");
  const packageRoot = join(inputs, "mxc-sdk-1.0.0");
  const fixtureRoot = join(packageRoot, "tests", "fixtures", "microvm");
  mkdirSync(fixtureRoot, { recursive: true });
  const manifest = join(packageRoot, "Cargo.toml");
  writeFileSync(manifest, '[package]\nname = "mxc-sdk"\nversion = "1.0.0"\n');
  for (const name of microvmFixtures) {
    if (mode === "packaged-missing-fixture" && name === "microvm_timeout.json") continue;
    copyFileSync(join(root, "src", "mxc-sdk", "tests", "fixtures", "microvm", name), join(fixtureRoot, name));
  }
  const archive = join(directory, "fixture.crate");
  const packed = spawnSync(
    "tar",
    ["--create", "--gzip", "--file", archive, "--directory", inputs, "mxc-sdk-1.0.0"],
    { encoding: "utf8", timeout: 30_000 }
  );
  assert.ifError(packed.error);
  assert.equal(packed.status, 0, packed.stdout + packed.stderr);
  return runScript(
    packaging,
    ["-OutDir", join(directory, "output"), "-VerifyMicrovmTests"],
    {
      PATH: tools + delimiter + process.env.PATH,
      MXC_CI_FIXTURE_MODE: mode,
      MXC_CI_PACKAGE_ARCHIVE: archive,
      MXC_CI_PACKAGE_TARGET: join(directory, "target"),
      MXC_CI_PACKAGE_MANIFEST: manifest,
    }
  );
}

test("package gate compiles MicroVM tests from the extracted archive", () => {
  const result = verifyPackage();
  assert.equal(result.status, 0, result.output);
  assert.match(result.output, /PACKAGE_COMPILED extracted nvx_e2e target/);
});

for (const [mode, message] of [
  ["packaged-missing-fixture", /Packaged MicroVM fixture is missing: microvm_timeout\.json/],
  ["packaged-build-failure", /packaged MicroVM test compilation failed with exit 29/],
]) {
  test(`package gate rejects ${mode}`, () => {
    const result = verifyPackage(mode);
    assert.notEqual(result.status, 0, result.output);
    assert.match(result.output, message);
    assert.doesNotMatch(result.output, /Compiled the MicroVM test target/);
  });
}

test("artifact dispatcher executes prebuilt SDK tests and preserves the log", () => {
  const directory = artifact();
  const result = dispatch(directory);
  assert.equal(result.status, 0, result.output);
  const log = readFileSync(join(directory, "logs", "microvm-nvx.log"), "utf8");
  assert.match(log, /VM_EXECUTED facade /);
  assert.match(log, /VM_EXECUTED executor /);
  assert.match(log, /VM_EXECUTED executor console interruption /);
});

for (const [mode, message] of [
  ["native-failure", /exited 23/],
  ["zero-tests", /executed no tests/],
  ["missing-facade", /did not execute the facade VM scenario/],
  ["missing-executor", /did not execute the executor VM scenario/],
  ["missing-configs", /did not execute the executor configs VM scenario/],
  ["missing-interruption", /did not execute the executor interruption VM scenario/],
  ["skipped", /skipped or filtered tests/],
  ["ignored", /skipped or filtered tests/],
]) {
  test(`artifact dispatcher fails closed for ${mode}`, () => {
    const result = dispatch(artifact(), mode);
    assert.notEqual(result.status, 0, result.output);
    assert.match(result.output, message);
  });
}

test("artifact dispatcher rejects a missing test payload", () => {
  const directory = artifact();
  rmSync(join(directory, "nvx-e2e-tests.exe"));
  const result = dispatch(directory);
  assert.notEqual(result.status, 0, result.output);
  assert.match(result.output, /Required CI artifact file is missing:[\s\S]*nvx-e2e-tests\.exe/);
});

test("artifact dispatcher rejects ARM64 instead of running the x64 suite", () => {
  const result = dispatch(artifact(), "", "arm64");
  assert.notEqual(result.status, 0, result.output);
  assert.match(result.output, /MicroVM validation requires x64/);
});

function stage(mode = "") {
  const directory = artifact();
  rmSync(join(directory, "nvx-e2e-tests.exe"));
  const result = runScript(
    staging,
    ["-BinaryDirectory", directory, "-Features", "microvm"],
    {
      PATH: tools + delimiter + process.env.PATH,
      MXC_CI_FIXTURE_MODE: mode,
      MXC_CI_FIXTURE_EXECUTABLE: fixture,
    }
  );
  return { ...result, directory };
}

test("staging uses Cargo's reported executable and checks VM test discovery", () => {
  const result = stage();
  assert.equal(result.status, 0, result.output);
  assert.deepEqual(
    readFileSync(join(result.directory, "nvx-e2e-tests.exe")),
    readFileSync(fixture)
  );
});

for (const [mode, message] of [
  ["cargo-failure", /cargo test --no-run failed with exit code 17/],
  ["cargo-no-artifact", /Expected one nvx_e2e test executable/],
  ["missing-discovery", /did not discover windows_x64::signed_bundle_facade_create_and_run/],
  ["missing-interruption-discovery", /did not discover windows_x64::signed_bundle_executor_console_interrupt/],
]) {
  test(`staging rejects ${mode}`, () => {
    const result = stage(mode);
    assert.notEqual(result.status, 0, result.output);
    assert.match(result.output, message);
    if (!["missing-discovery", "missing-interruption-discovery"].includes(mode)) {
      assert.equal(existsSync(join(result.directory, "nvx-e2e-tests.exe")), false);
    }
  });
}
