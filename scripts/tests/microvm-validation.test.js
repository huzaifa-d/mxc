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
const { delimiter, join, resolve } = require("node:path");
const { spawnSync } = require("node:child_process");
const { pathToFileURL } = require("node:url");
const { stripVTControlCharacters } = require("node:util");

const root = resolve(__dirname, "..", "..");
const dispatcher = join(root, "scripts", "ci", "run_backend_validation_tests.ps1");
const staging = join(root, "scripts", "ci", "stage-nvx-validation-tests.ps1");
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
  mkdirSync(join(root, "target"), { recursive: true });
  scratch = mkdtempSync(join(root, "target", "mxc-microvm-validation-"));
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
        assert!(args.contains(&"--locked".to_owned()));
        assert!(args.contains(&"--release".to_owned()));
        assert!(args.contains(&"--no-run".to_owned()));
        assert!(args.windows(2).any(|pair| pair == ["--test", "nvx_e2e"]));
        assert!(args.windows(2).any(|pair| pair == ["--test", "nvx_phase3_e2e"]));
        assert!(args.windows(2).any(|pair| pair == ["--target", "x86_64-pc-windows-msvc"]));
        if mode == "cargo-failure" {
            eprintln!("fixture cargo failed");
            process::exit(17);
        }
        if mode != "cargo-no-artifact" {
            let executable = env::var("MXC_CI_FIXTURE_EXECUTABLE").unwrap();
            assert!(Path::new(&executable).is_file());
            println!("{{\"reason\":\"compiler-artifact\",\"target\":{{\"name\":\"nvx_e2e\"}},\"profile\":{{\"test\":true}},\"executable\":{executable:?}}}");
            if mode != "missing-phase3-artifact" {
                println!("{{\"reason\":\"compiler-artifact\",\"target\":{{\"name\":\"nvx_phase3_e2e\"}},\"profile\":{{\"test\":true}},\"executable\":{executable:?}}}");
            }
        }
        return;
    }
    if args.first().map(String::as_str) == Some("--operation") {
        match args[1].as_str() {
            "provision" => println!("{{\"result\":{{\"sandboxId\":\"microvm:fixture\"}}}}"),
            "exec" if mode == "harness-failure" => process::exit(19),
            "exec" => println!("EXECUTOR_NVX_OK"),
            _ => println!("{{\"result\":{{}}}}"),
        }
        return;
    }
    let scenarios = [
        "exact_alpha_json_runs_twice_through_signed_nvx_agent",
        "typed_lifecycle_reuses_running_microvm",
        "deprovisioning_one_microvm_does_not_disrupt_another",
        "typed_lifecycle_streams_stdin_stdout_and_cancels",
        "typed_create_and_run_requires_experimental_and_streams",
        "lifecycle_filesystem_policy_is_enforced",
        "exact_json_lifecycle_routes_microvm_end_to_end",
        "lifecycle_directional_network_policy_is_enforced",
        "lifecycle_proxy_routes_guest_http",
        "pty_and_exec_time_proxy_fail_before_workload_launch",
    ];
    if args == ["--list"] {
        println!("windows_x64::host_only_executor_request_matrix: test");
        println!("windows_x64::signed_bundle_executor_configs: test");
        println!("windows_x64::signed_bundle_executor_create_and_run: test");
        if mode != "missing-discovery" {
            println!("windows_x64::signed_bundle_facade_create_and_run: test");
        }
        println!("discovery_without_bundle_is_read_only: test");
        println!("powershell_lifecycle_failures_report_both_streams_and_preserve_cleanup: test");
        for scenario in scenarios {
            if mode != "missing-phase3-discovery" || scenario != "typed_lifecycle_reuses_running_microvm" {
                println!("{scenario}: test");
            }
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
    if exe.file_stem().unwrap() == "nvx-phase3-e2e-tests" {
        if mode == "phase3-native-failure" { process::exit(29); }
        if mode == "phase3-zero-tests" {
            println!("test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;");
            return;
        }
        for scenario in scenarios {
            if mode != format!("missing-phase3-{scenario}") {
                println!("VM_EXECUTED phase3 {scenario}");
            }
        }
        if mode == "phase3-skipped" { println!("SKIPPED: fixture VM unavailable"); }
        let ignored = if mode == "phase3-ignored" { 1 } else { 0 };
        println!("test result: ok. 10 passed; 0 failed; {ignored} ignored; 0 measured; 0 filtered out;");
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
    if mode == "skipped" {
        println!("SKIPPED: fixture VM unavailable");
    }
    let ignored = if mode == "ignored" { 1 } else { 0 };
    println!("test result: ok. 6 passed; 0 failed; {ignored} ignored; 0 measured; 0 filtered out;");
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
  copyFileSync(fixture, join(directory, "nvx-phase3-e2e-tests.exe"));
  const scripts = join(directory, "nvx-validation", "tests", "scripts");
  mkdirSync(scripts, { recursive: true });
  copyFileSync(
    join(root, "tests", "scripts", "run_microvm_state_aware_tests.ps1"),
    join(scripts, "run_microvm_state_aware_tests.ps1")
  );
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
    ["-Backend", "microvm", "-BinaryDirectory", directory, "-Architecture", architecture],
    {
      MXC_CI_FIXTURE_MODE: mode,
      RUNNER_TEMP: join(directory, "logs"),
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
  assert.ok(workflow.includes("src/target/${{ matrix.target }}/release/nvx-phase3-e2e-tests.exe"));
  assert.ok(workflow.includes("src/target/${{ matrix.target }}/release/nvx-validation/"));
  assert.ok(workflow.includes("src/target/${{ matrix.target }}/release/aci-edge-sandboxes/"));
  assert.equal(existsSync(join(root, ".github", "workflows", "microvm-e2e.yml")), false);
});

test("artifact dispatcher executes prebuilt SDK tests and preserves the log", () => {
  const directory = artifact();
  const result = dispatch(directory);
  assert.equal(result.status, 0, result.output);
  const log = readFileSync(join(directory, "logs", "microvm-nvx.log"), "utf8");
  assert.match(log, /VM_EXECUTED facade /);
  assert.match(log, /VM_EXECUTED executor /);
  const phase3 = readFileSync(join(directory, "logs", "microvm-nvx-phase3.log"), "utf8");
  assert.match(phase3, /VM_EXECUTED phase3 typed_lifecycle_streams_stdin_stdout_and_cancels/);
  const harness = readFileSync(join(directory, "logs", "microvm-lifecycle-executor.log"), "utf8");
  assert.match(harness, /VM_EXECUTED executor lifecycle provision\/start\/exec\/stop\/deprovision/);
});

for (const [mode, message] of [
  ["native-failure", /exited 23/],
  ["zero-tests", /executed no tests/],
  ["missing-facade", /did not execute the facade VM scenario/],
  ["missing-executor", /did not execute the executor VM scenario/],
  ["missing-configs", /did not execute the executor configs VM scenario/],
  ["skipped", /skipped or filtered tests/],
  ["ignored", /skipped or filtered tests/],
  ["phase3-native-failure", /lifecycle\/streaming tests exited 29/],
  ["phase3-zero-tests", /lifecycle\/streaming tests executed no tests/],
  ["phase3-skipped", /lifecycle\/streaming validation skipped or filtered tests/],
  ["phase3-ignored", /lifecycle\/streaming validation skipped or filtered tests/],
  ["harness-failure", /executor lifecycle harness failed/],
  ...[
    "typed_lifecycle_reuses_running_microvm",
    "typed_lifecycle_streams_stdin_stdout_and_cancels",
    "typed_create_and_run_requires_experimental_and_streams",
    "lifecycle_filesystem_policy_is_enforced",
    "exact_json_lifecycle_routes_microvm_end_to_end",
    "lifecycle_directional_network_policy_is_enforced",
    "lifecycle_proxy_routes_guest_http",
  ].map((name) => [`missing-phase3-${name}`, new RegExp(`did not execute ${name}`)]),
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

for (const filename of ["nvx-phase3-e2e-tests.exe", join("nvx-validation", "tests", "scripts", "run_microvm_state_aware_tests.ps1")]) {
  test(`artifact dispatcher rejects missing ${filename}`, () => {
    const directory = artifact();
    rmSync(join(directory, filename));
    const result = dispatch(directory);
    assert.notEqual(result.status, 0, result.output);
    assert.match(result.output, /Required CI artifact file is missing/);
  });
}

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
  assert.deepEqual(
    readFileSync(join(result.directory, "nvx-phase3-e2e-tests.exe")),
    readFileSync(fixture)
  );
  assert.ok(existsSync(join(result.directory, "nvx-validation", "tests", "scripts", "run_microvm_state_aware_tests.ps1")));
});

for (const [mode, message] of [
  ["cargo-failure", /cargo test --no-run failed with exit code 17/],
  ["cargo-no-artifact", /Expected one nvx_e2e test executable/],
  ["missing-discovery", /did not discover windows_x64::signed_bundle_facade_create_and_run/],
  ["missing-phase3-artifact", /Expected one nvx_phase3_e2e test executable/],
  ["missing-phase3-discovery", /did not discover typed_lifecycle_reuses_running_microvm/],
]) {
  test(`staging rejects ${mode}`, () => {
    const result = stage(mode);
    assert.notEqual(result.status, 0, result.output);
    assert.match(result.output, message);
    if (mode === "cargo-failure" || mode === "cargo-no-artifact") {
      assert.equal(existsSync(join(result.directory, "nvx-e2e-tests.exe")), false);
    }
  });
}
