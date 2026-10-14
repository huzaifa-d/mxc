#![cfg(all(windows, target_arch = "x86_64", feature = "microvm"))]

use std::time::{SystemTime, UNIX_EPOCH};

use mxc_sdk::v1::{ErrorCode, WaitResult};

fn process_only_request(command: &str) -> serde_json::Value {
    serde_json::json!({
        "version": "1.1.0-alpha",
        "containment": "microvm",
        "process": {
            "commandLine": command,
            "timeout": 30_000
        }
    })
}

fn run_nonce(label: &str) {
    let nonce = format!(
        "{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos()
    );
    let command = format!("printf '{}\\n'; uname -s", nonce.replace('\'', "'\"'\"'"));
    let result = mxc_sdk::__ffi::run_json(&process_only_request(&command).to_string(), true)
        .expect("exact alpha MicroVM request should run through direct NVX");
    assert_eq!(
        result.outcome,
        WaitResult::Exited(0),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    let stdout = String::from_utf8_lossy(&result.stdout);
    assert!(
        stdout.contains(&nonce),
        "stdout did not contain nonce: {stdout}"
    );
    assert!(
        stdout.contains("Linux"),
        "stdout did not identify Linux: {stdout}"
    );
}

#[test]
fn experimental_opt_in_is_required_before_backend_discovery() {
    let request = process_only_request("printf ok");
    let error = mxc_sdk::__ffi::run_json(&request.to_string(), false).unwrap_err();
    assert_eq!(error.code, ErrorCode::BackendUnavailable);
    assert!(error.message.contains("experimental"));
}

#[test]
fn unsupported_policy_is_rejected_before_runtime_discovery() {
    let mut request = process_only_request("printf ok");
    request["filesystem"] = serde_json::json!({
        "readwritePaths": ["C:\\work"]
    });
    let error = mxc_sdk::__ffi::run_json(&request.to_string(), true).unwrap_err();
    assert_eq!(error.code, ErrorCode::PolicyValidation);
    assert_eq!(
        error.message,
        "Phase 1 NVX does not support filesystem policy"
    );
}

#[test]
fn explicit_missing_artifact_directory_is_backend_unavailable() {
    if std::env::var_os("MXC_NVX_MISSING_ARTIFACTS_CHILD").is_some() {
        let request = process_only_request("printf ok");
        let error = mxc_sdk::__ffi::run_json(&request.to_string(), true).unwrap_err();
        assert_eq!(error.code, ErrorCode::BackendUnavailable);
        assert!(error.message.contains("NVX"));
        return;
    }

    let missing =
        std::env::temp_dir().join(format!("missing-nvx-artifacts-{}", std::process::id()));
    let output = std::process::Command::new(std::env::current_exe().expect("current test binary"))
        .arg("--exact")
        .arg("explicit_missing_artifact_directory_is_backend_unavailable")
        .arg("--nocapture")
        .env("MXC_NVX_MISSING_ARTIFACTS_CHILD", "1")
        .env("NVX_ARTIFACTS_DIR", missing)
        .output()
        .expect("launch isolated missing-artifacts test");
    assert!(
        output.status.success(),
        "isolated missing-artifacts test failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "requires Windows x64 and WHP"]
fn exact_alpha_json_runs_twice_through_direct_nvx() {
    run_nonce("mxc-nvx-first");
    run_nonce("mxc-nvx-second");
}
