#![cfg(all(windows, target_arch = "x86_64", feature = "microvm"))]

use std::time::{SystemTime, UNIX_EPOCH};
use std::{io::Read, io::Write};

use mxc_sdk::v1::{
    self, ContainerRequest, Containment, DeprovisionOptions, ErrorCode, ExecutionRequest,
    FilesystemPolicy, NetworkAction, NetworkEgressPolicy, NetworkIngressPolicy, NetworkPeerPolicy,
    NetworkPolicy, NetworkPortPolicy, NetworkProtocol, NetworkRulePolicy, NetworkRuntimeConfig,
    ProvisionOptions, ProvisionRequest, RunInContainerOptions, RunOptions, SpawnInContainerOptions,
    SpawnInContainerWithPtyOptions, SpawnOptions, StartOptions, StopOptions, WaitResult,
};

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
        .expect("exact alpha MicroVM request should run through the signed NVX agent");
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

fn guest_path(host: &std::path::Path) -> String {
    let path = std::path::absolute(host).expect("absolute host path");
    let text = path.to_string_lossy().replace('\\', "/");
    assert!(text.as_bytes().get(1) == Some(&b':'), "{text}");
    format!("/mnt/{}/{}", text[..1].to_ascii_lowercase(), &text[3..])
}

#[test]
fn experimental_opt_in_is_required_before_backend_discovery() {
    let request = process_only_request("printf ok");
    let error = mxc_sdk::__ffi::run_json(&request.to_string(), false).unwrap_err();
    assert_eq!(error.code, ErrorCode::BackendUnavailable);
    assert!(error.message.contains("experimental"));
}

#[test]
fn unsupported_ui_policy_is_rejected_before_runtime_discovery() {
    let mut request = process_only_request("printf ok");
    request["ui"] = serde_json::json!({"disable": true});
    let error = mxc_sdk::__ffi::run_json(&request.to_string(), true).unwrap_err();
    assert_eq!(error.code, ErrorCode::PolicyValidation);
    assert_eq!(error.message, "NVX does not support UI policy");
}

#[test]
fn missing_bundle_is_backend_unavailable() {
    if std::env::var_os("MXC_NVX_MISSING_BUNDLE_CHILD").is_some() {
        let request = process_only_request("printf ok");
        let error = mxc_sdk::__ffi::run_json(&request.to_string(), true).unwrap_err();
        assert_eq!(error.code, ErrorCode::BackendUnavailable);
        assert!(error.message.contains("MXC_NVX_BUNDLE_DIR"));
        return;
    }

    let output = std::process::Command::new(std::env::current_exe().expect("current test binary"))
        .arg("--exact")
        .arg("missing_bundle_is_backend_unavailable")
        .arg("--nocapture")
        .env("MXC_NVX_MISSING_BUNDLE_CHILD", "1")
        .env_remove("MXC_NVX_BUNDLE_DIR")
        .output()
        .expect("launch isolated missing-bundle test");
    assert!(
        output.status.success(),
        "isolated missing-bundle test failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "requires Windows x64, WHP, MXC_NVX_BUNDLE_DIR, and MCR access"]
fn exact_alpha_json_runs_twice_through_signed_nvx_agent() {
    run_nonce("mxc-nvx-first");
    run_nonce("mxc-nvx-second");
}

#[test]
#[ignore = "requires Windows x64, WHP, MXC_NVX_BUNDLE_DIR, and MCR access"]
fn typed_lifecycle_reuses_running_microvm() {
    assert!(
        v1::available_backends()
            .iter()
            .any(|backend| backend.backend == "microvm"),
        "configured signed NVX runtime should be discoverable"
    );
    let provisioned = v1::experimental::container::provision_container(
        ProvisionRequest::microvm(Some(512)),
        ProvisionOptions::default(),
    )
    .expect("provision MicroVM");
    assert!(provisioned.container_id.as_str().starts_with("microvm:"));
    v1::experimental::container::start_container(
        &provisioned.container_id,
        StartOptions::default(),
    )
    .expect("start MicroVM");

    let first = v1::experimental::container::run_in_container(
        &provisioned.container_id,
        ExecutionRequest::new("printf first > /tmp/mxc-state"),
        RunInContainerOptions::default(),
    )
    .expect("first exec");
    assert_eq!(first.outcome, WaitResult::Exited(0));
    let second = v1::experimental::container::run_in_container(
        &provisioned.container_id,
        ExecutionRequest::new("cat /tmp/mxc-state"),
        RunInContainerOptions::default(),
    )
    .expect("second exec");
    assert_eq!(second.outcome, WaitResult::Exited(0));
    assert_eq!(second.stdout, b"first");

    v1::experimental::container::stop_container(&provisioned.container_id, StopOptions::default())
        .expect("stop MicroVM");
    v1::experimental::container::deprovision_container(
        &provisioned.container_id,
        DeprovisionOptions::default(),
    )
    .expect("deprovision MicroVM");
}

#[test]
#[ignore = "requires Windows x64, WHP, MXC_NVX_BUNDLE_DIR, and MCR access"]
fn typed_lifecycle_streams_stdin_stdout_and_cancels() {
    let provisioned = v1::experimental::container::provision_container(
        ProvisionRequest::microvm(None),
        ProvisionOptions::default(),
    )
    .expect("provision MicroVM");
    v1::experimental::container::start_container(
        &provisioned.container_id,
        StartOptions::default(),
    )
    .expect("start MicroVM");

    let mut process = v1::experimental::container::spawn_in_container(
        &provisioned.container_id,
        ExecutionRequest::new("cat"),
        SpawnInContainerOptions::default(),
    )
    .expect("spawn cat");
    let mut stdin = process.take_stdin().expect("piped stdin");
    let mut stdout = process.take_stdout().expect("piped stdout");
    let input = vec![b'x'; 2 * 1024 * 1024];
    let reader = std::thread::spawn(move || {
        let mut output = Vec::new();
        stdout.read_to_end(&mut output).unwrap();
        output
    });
    stdin.write_all(&input).unwrap();
    drop(stdin);
    assert_eq!(process.wait().unwrap(), WaitResult::Exited(0));
    assert_eq!(reader.join().unwrap(), input);

    let mut sleeper = v1::experimental::container::spawn_in_container(
        &provisioned.container_id,
        ExecutionRequest::new("sleep 120"),
        SpawnInContainerOptions::default(),
    )
    .expect("spawn sleeper");
    sleeper.kill().expect("cancel sleeper");
    assert_eq!(sleeper.wait().unwrap(), WaitResult::Exited(137));

    let mut timed_request = ExecutionRequest::new("sleep 120");
    timed_request.timeout_ms = Some(100);
    let timed = v1::experimental::container::run_in_container(
        &provisioned.container_id,
        timed_request,
        RunInContainerOptions::default(),
    )
    .expect("timed exec");
    assert_eq!(timed.outcome, WaitResult::TimedOut);

    v1::experimental::container::stop_container(&provisioned.container_id, StopOptions::default())
        .expect("stop MicroVM");
    v1::experimental::container::deprovision_container(
        &provisioned.container_id,
        DeprovisionOptions::default(),
    )
    .expect("deprovision MicroVM");
}

#[test]
#[ignore = "requires Windows x64, WHP, MXC_NVX_BUNDLE_DIR, and MCR access"]
fn typed_create_and_run_requires_experimental_and_streams() {
    let mut denied = ContainerRequest::new("printf should-not-run");
    denied.containment = Containment::MicroVm;
    let error = v1::run(denied, RunOptions::default()).unwrap_err();
    assert_eq!(error.code, ErrorCode::BackendUnavailable);
    assert!(error.message.contains("experimental"));

    let mut request = ContainerRequest::new("cat");
    request.containment = Containment::MicroVm;
    let mut process =
        v1::experimental::spawn(request, SpawnOptions::default()).expect("spawn one-shot cat");
    let mut stdin = process.take_stdin().expect("one-shot stdin");
    let mut stdout = process.take_stdout().expect("one-shot stdout");
    stdin.write_all(b"one-shot-stream").unwrap();
    drop(stdin);
    assert_eq!(process.wait().unwrap(), WaitResult::Exited(0));
    let mut output = Vec::new();
    stdout.read_to_end(&mut output).unwrap();
    assert_eq!(output, b"one-shot-stream");
}

#[test]
#[ignore = "requires Windows x64, WHP, MXC_NVX_BUNDLE_DIR, and MCR access"]
fn lifecycle_filesystem_policy_is_enforced() {
    let root = tempfile::tempdir().unwrap();
    let readonly = root.path().join("readonly");
    let readwrite = root.path().join("readwrite");
    std::fs::create_dir_all(&readonly).unwrap();
    std::fs::create_dir_all(&readwrite).unwrap();
    let input = readonly.join("input.txt");
    let secret = readonly.join("secret.txt");
    let output = readwrite.join("output.txt");
    std::fs::write(&input, "READ_ONLY").unwrap();
    std::fs::write(&secret, "SECRET").unwrap();

    let mut provision = ProvisionRequest::microvm(None);
    provision.set_filesystem(FilesystemPolicy {
        readonly_paths: vec![readonly.to_string_lossy().into_owned()],
        readwrite_paths: vec![readwrite.to_string_lossy().into_owned()],
        denied_paths: vec![secret.to_string_lossy().into_owned()],
        clear_policy_on_exit: None,
    });
    let provisioned =
        v1::experimental::container::provision_container(provision, ProvisionOptions::default())
            .unwrap();
    v1::experimental::container::start_container(
        &provisioned.container_id,
        StartOptions::default(),
    )
    .unwrap();
    let command = format!(
        "test \"$(cat '{}')\" = READ_ONLY && ! printf bad > '{}' && printf GUEST_OUTPUT > '{}' && ! cat '{}'",
        guest_path(&input),
        guest_path(&input),
        guest_path(&output),
        guest_path(&secret)
    );
    let result = v1::experimental::container::run_in_container(
        &provisioned.container_id,
        ExecutionRequest::new(command),
        RunInContainerOptions::default(),
    )
    .unwrap();
    assert_eq!(result.outcome, WaitResult::Exited(0));
    assert_eq!(std::fs::read_to_string(output).unwrap(), "GUEST_OUTPUT");
    assert_eq!(std::fs::read_to_string(input).unwrap(), "READ_ONLY");
    v1::experimental::container::stop_container(&provisioned.container_id, StopOptions::default())
        .unwrap();
    v1::experimental::container::deprovision_container(
        &provisioned.container_id,
        DeprovisionOptions::default(),
    )
    .unwrap();
}

#[test]
#[ignore = "requires Windows x64, WHP, MXC_NVX_BUNDLE_DIR, and MCR access"]
fn exact_json_lifecycle_routes_microvm_end_to_end() {
    let provision = serde_json::json!({
        "version": "1.1.0-alpha",
        "phase": "provision",
        "containment": "microvm"
    });
    let response = mxc_sdk::__ffi::run_lifecycle_json(&provision.to_string(), false, true).unwrap();
    let envelope: serde_json::Value = serde_json::from_str(&response).unwrap();
    let id = envelope["result"]["sandboxId"].as_str().unwrap();
    assert!(id.starts_with("microvm:"));

    for phase in ["start", "stop", "deprovision"] {
        if phase == "stop" {
            let exec = serde_json::json!({
                "version": "1.1.0-alpha",
                "phase": "exec",
                "sandboxId": id,
                "process": {"commandLine": "printf JSON_LIFECYCLE"}
            });
            let result = mxc_sdk::__ffi::execute_lifecycle_json(&exec.to_string(), true).unwrap();
            let output = result.wait_with_output().unwrap();
            assert_eq!(output.outcome, WaitResult::Exited(0));
            assert_eq!(output.stdout, b"JSON_LIFECYCLE");
        }

        let request = serde_json::json!({
            "version": "1.1.0-alpha",
            "phase": phase,
            "sandboxId": id
        });
        mxc_sdk::__ffi::run_lifecycle_json(&request.to_string(), false, true).unwrap();
    }
}

fn run_with_network(network: NetworkPolicy, command: &str) -> v1::ExecutionResult {
    let mut provision = ProvisionRequest::microvm(None);
    provision.set_network(network);
    let provisioned =
        v1::experimental::container::provision_container(provision, ProvisionOptions::default())
            .unwrap();
    v1::experimental::container::start_container(
        &provisioned.container_id,
        StartOptions::default(),
    )
    .unwrap();
    let result = v1::experimental::container::run_in_container(
        &provisioned.container_id,
        ExecutionRequest::new(command),
        RunInContainerOptions::default(),
    )
    .unwrap();
    v1::experimental::container::stop_container(&provisioned.container_id, StopOptions::default())
        .unwrap();
    v1::experimental::container::deprovision_container(
        &provisioned.container_id,
        DeprovisionOptions::default(),
    )
    .unwrap();
    result
}

#[test]
#[ignore = "requires Windows x64, WHP, MXC_NVX_BUNDLE_DIR, MCR access, and internet egress"]
fn lifecycle_directional_network_policy_is_enforced() {
    let deny = NetworkPolicy {
        egress: Some(NetworkEgressPolicy {
            default: Some(NetworkAction::Deny),
            ..Default::default()
        }),
        ingress: Some(NetworkIngressPolicy {
            default: Some(NetworkAction::Deny),
            host_loopback: Some(NetworkAction::Deny),
        }),
        runtime_config: None,
    };
    let blocked = run_with_network(
        deny,
        "if curl -k --connect-timeout 3 --silent https://1.1.1.1 >/dev/null; then exit 1; else printf NETWORK_BLOCKED; fi",
    );
    assert_eq!(blocked.outcome, WaitResult::Exited(0));
    assert_eq!(blocked.stdout, b"NETWORK_BLOCKED");

    let allow = NetworkPolicy {
        egress: Some(NetworkEgressPolicy {
            default: Some(NetworkAction::Deny),
            allow: Some(vec![NetworkRulePolicy {
                to: Some(vec![NetworkPeerPolicy::new("1.1.1.1/32")]),
                ports: Some(vec![NetworkPortPolicy {
                    protocol: Some(NetworkProtocol::Tcp),
                    port: Some(443),
                    end_port: None,
                }]),
            }]),
            deny: None,
        }),
        ingress: Some(NetworkIngressPolicy {
            default: Some(NetworkAction::Deny),
            host_loopback: Some(NetworkAction::Deny),
        }),
        runtime_config: None,
    };
    let allowed = run_with_network(
        allow,
        "curl -k --fail --connect-timeout 5 --silent https://1.1.1.1 >/dev/null && printf NETWORK_ALLOWED",
    );
    assert_eq!(allowed.outcome, WaitResult::Exited(0));
    assert_eq!(allowed.stdout, b"NETWORK_ALLOWED");
}

#[test]
#[ignore = "requires Windows x64, WHP, MXC_NVX_BUNDLE_DIR, and MCR access"]
fn lifecycle_proxy_routes_guest_http() {
    use std::net::TcpListener;
    use std::time::{Duration, Instant};

    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let proxy = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut request = Vec::new();
                    let mut buffer = [0u8; 1024];
                    loop {
                        let read = stream.read(&mut buffer).unwrap();
                        if read == 0 {
                            break;
                        }
                        request.extend_from_slice(&buffer[..read]);
                        if request.windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                    }
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nPROXY_OK",
                        )
                        .unwrap();
                    return;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "guest never reached proxy");
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(error) => panic!("proxy accept failed: {error}"),
            }
        }
    });
    let network = NetworkPolicy {
        egress: Some(NetworkEgressPolicy {
            default: Some(NetworkAction::Deny),
            ..Default::default()
        }),
        ingress: Some(NetworkIngressPolicy {
            default: Some(NetworkAction::Deny),
            host_loopback: Some(NetworkAction::Deny),
        }),
        runtime_config: Some(NetworkRuntimeConfig {
            network_proxy: Some(format!("http://127.0.0.1:{port}")),
        }),
    };
    let result = run_with_network(
        network,
        "curl --fail --silent http://example.invalid/proxy-test",
    );
    proxy.join().unwrap();
    assert_eq!(result.outcome, WaitResult::Exited(0));
    assert_eq!(result.stdout, b"PROXY_OK");
}

#[test]
#[ignore = "requires Windows x64, WHP, MXC_NVX_BUNDLE_DIR, and MCR access"]
fn pty_and_exec_time_proxy_fail_before_workload_launch() {
    let provisioned = v1::experimental::container::provision_container(
        ProvisionRequest::microvm(None),
        ProvisionOptions::default(),
    )
    .unwrap();
    v1::experimental::container::start_container(
        &provisioned.container_id,
        StartOptions::default(),
    )
    .unwrap();

    let pty = v1::experimental::container::spawn_in_container_with_pty(
        &provisioned.container_id,
        ExecutionRequest::new("touch /tmp/pty-ran"),
        SpawnInContainerWithPtyOptions::default(),
    )
    .unwrap_err();
    assert_eq!(pty.code, ErrorCode::UnsupportedPhase);

    let proxy_exec = serde_json::json!({
        "version": "1.1.0-alpha",
        "phase": "exec",
        "sandboxId": provisioned.container_id.as_str(),
        "process": {"commandLine": "touch /tmp/proxy-ran"},
        "runtimeConfig": {"networkProxy": "http://127.0.0.1:3128"}
    });
    let proxy_error = match mxc_sdk::__ffi::execute_lifecycle_json(&proxy_exec.to_string(), true) {
        Ok(_) => panic!("exec-time proxy must be rejected before launch"),
        Err(error) => error,
    };
    assert_eq!(proxy_error.code, ErrorCode::PolicyValidation);

    let result = v1::experimental::container::run_in_container(
        &provisioned.container_id,
        ExecutionRequest::new("test ! -e /tmp/pty-ran && test ! -e /tmp/proxy-ran"),
        RunInContainerOptions::default(),
    )
    .unwrap();
    assert_eq!(result.outcome, WaitResult::Exited(0));

    v1::experimental::container::stop_container(&provisioned.container_id, StopOptions::default())
        .unwrap();
    v1::experimental::container::deprovision_container(
        &provisioned.container_id,
        DeprovisionOptions::default(),
    )
    .unwrap();
}
