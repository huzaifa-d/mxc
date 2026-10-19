// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Minimal create-and-run adapter for the signed bundled NVX agent.

use std::io::Write;
use std::time::Duration;

use aci_edge_sandboxes::{ExecOutcome, ExecRequest, ProvisionRequest};

use crate::mxc_common::audit::{AuditEvent, AuditEventName};
use crate::mxc_common::logger::Logger;
use crate::mxc_common::models::{ExecutionRequest, FailurePhase, ScriptResponse};
use crate::mxc_common::mxc_error::{MxcError, MxcErrorCode};
use crate::mxc_common::script_runner::ScriptRunner;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapturedOutcome {
    Exited(i32),
    TimedOut,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedRun {
    pub outcome: CapturedOutcome,
    pub warnings: Vec<String>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct NvxRunner;

impl NvxRunner {
    pub fn new() -> Self {
        Self
    }

    pub fn run_captured(
        &mut self,
        request: &ExecutionRequest,
        logger: &mut Logger,
    ) -> Result<CapturedRun, MxcError> {
        super::policy::validate_request(request)?;
        let state_root = tempfile::Builder::new()
            .prefix(&format!("mxc-nvx-{}-", std::process::id()))
            .tempdir()
            .map_err(|error| {
                MxcError::backend_unavailable(format!(
                    "cannot create a private NVX state directory: {error}"
                ))
            })?;
        let prepared = (|| {
            let client = super::runtime::create_client(state_root.path())?;
            client.probe().map_err(super::runtime::map_nvx_error)?;
            let provisioned = client
                .provision_with(&ProvisionRequest::new(), &super::runtime::sandbox_spec())
                .map_err(super::runtime::map_nvx_error)?;
            Ok((client, provisioned.sandbox_id))
        })();
        let (client, sandbox_id) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                let cleanup = state_root
                    .close()
                    .err()
                    .map(|error| {
                        MxcError::backend_error(format!("cannot remove NVX state: {error}"))
                    })
                    .into_iter()
                    .collect();
                return finish_run(Err(error), cleanup, logger);
            }
        };
        let identity = sandbox_id.to_string();
        logger.log_audit_event(
            &AuditEvent::new(AuditEventName::SandboxIdentity)
                .str("identity", &identity)
                .str("backend", "microvm")
                .str("runtime", "signed-bundled-agent"),
        );
        let primary = (|| {
            client
                .start(&sandbox_id)
                .map_err(super::runtime::map_nvx_error)?;
            client
                .exec(&sandbox_id, &exec_request(request))
                .map_err(super::runtime::map_nvx_error)?
                .wait_with_output()
                .map_err(super::runtime::map_nvx_error)
        })();

        let stop_error = client
            .stop(&sandbox_id)
            .err()
            .map(super::runtime::map_nvx_error);
        let stop_error = match stop_error {
            Some(error) if primary.is_err() && error.code == MxcErrorCode::AlreadyStopped => None,
            other => other,
        };
        let deprovision_error = client
            .deprovision(&sandbox_id)
            .err()
            .map(super::runtime::map_nvx_error);
        let retain_state = deprovision_error.is_some();
        let mut cleanup_errors: Vec<MxcError> = [stop_error, deprovision_error]
            .into_iter()
            .flatten()
            .collect();
        drop(client);
        if retain_state {
            let retained = state_root.keep();
            cleanup_errors.push(MxcError::backend_error(format!(
                "NVX state retained for recovery after deprovision failure: {}",
                retained.display()
            )));
        } else if let Err(error) = state_root.close() {
            cleanup_errors.push(MxcError::backend_error(format!(
                "cannot remove NVX state directory: {error}"
            )));
        }
        logger.log_audit_event(
            &AuditEvent::new(AuditEventName::SandboxTornDown)
                .str("identity", &identity)
                .str("backend", "microvm")
                .str(
                    "status",
                    if cleanup_errors.is_empty() {
                        "ok"
                    } else {
                        "failed"
                    },
                )
                .bool("state_retained", retain_state),
        );
        let output = finish_run(primary, cleanup_errors, logger)?;

        Ok(CapturedRun {
            outcome: map_outcome(output.outcome)?,
            warnings: Vec::new(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

fn finish_run<T>(
    primary: Result<T, MxcError>,
    cleanup_errors: Vec<MxcError>,
    logger: &mut Logger,
) -> Result<T, MxcError> {
    match primary {
        Ok(output) if cleanup_errors.is_empty() => Ok(output),
        Ok(_) => Err(MxcError::backend_error(format!(
            "NVX cleanup failed after workload completion: {}",
            cleanup_errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        ))),
        Err(mut error) => {
            for cleanup in cleanup_errors {
                logger.warning_line(&format!("NVX cleanup failed: {cleanup}"));
                error.message.push_str("; cleanup failure: ");
                error.message.push_str(&cleanup.to_string());
            }
            Err(error)
        }
    }
}

impl ScriptRunner for NvxRunner {
    fn validate_runner(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        super::policy::validate_request(request)
            .map_err(|error| ScriptResponse::rejected(&error.message))
    }

    fn execute(&mut self, request: &ExecutionRequest, logger: &mut Logger) -> ScriptResponse {
        let result = self.run_captured(request, logger).and_then(|result| {
            captured_to_script_response(
                result,
                &mut std::io::stdout().lock(),
                &mut std::io::stderr().lock(),
            )
        });
        match result {
            Ok(response) => response,
            Err(error) if error.code == MxcErrorCode::PolicyValidation => {
                ScriptResponse::rejected(&error.message)
            }
            Err(error) => ScriptResponse {
                exit_code: -1,
                error_message: error.to_string(),
                failure_phase: if error.code == MxcErrorCode::BackendUnavailable {
                    FailurePhase::BackendUnavailable
                } else {
                    FailurePhase::PostLaunchFailed
                },
                ..Default::default()
            },
        }
    }
}

fn map_outcome(outcome: ExecOutcome) -> Result<CapturedOutcome, MxcError> {
    match outcome {
        ExecOutcome::Exited(code) => Ok(CapturedOutcome::Exited(code)),
        ExecOutcome::TimedOut => Ok(CapturedOutcome::TimedOut),
        ExecOutcome::Signaled(signal) => {
            Ok(CapturedOutcome::Exited(128_i32.saturating_add(signal)))
        }
        other => Err(MxcError::backend_error(format!(
            "NVX workload did not complete normally: {other}"
        ))),
    }
}

fn captured_to_script_response(
    result: CapturedRun,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<ScriptResponse, MxcError> {
    stdout
        .write_all(&result.stdout)
        .and_then(|()| stdout.flush())
        .map_err(|error| MxcError::backend_error(format!("cannot relay NVX stdout: {error}")))?;
    stderr
        .write_all(&result.stderr)
        .and_then(|()| stderr.flush())
        .map_err(|error| MxcError::backend_error(format!("cannot relay NVX stderr: {error}")))?;
    Ok(match result.outcome {
        CapturedOutcome::Exited(exit_code) => ScriptResponse {
            exit_code,
            ..Default::default()
        },
        CapturedOutcome::TimedOut => ScriptResponse {
            exit_code: -1,
            error_message: "NVX workload timed out".to_string(),
            failure_phase: FailurePhase::Timeout,
            ..Default::default()
        },
    })
}

fn exec_request(request: &ExecutionRequest) -> ExecRequest {
    let mut exec = ExecRequest::command_line(request.script_code.clone());
    if request.script_timeout != 0 {
        exec = exec.with_timeout(Duration::from_millis(u64::from(request.script_timeout)));
    }
    if !request.working_directory.is_empty() {
        exec = exec.with_cwd(request.working_directory.clone());
    }
    if let Some(environment) = &request.env {
        exec = exec.with_envs(environment.clone());
    }
    exec.with_inherit_default_env(request.inherit_default_env)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_exit_signal_and_timeout_outcomes() {
        assert_eq!(
            map_outcome(ExecOutcome::Exited(42)).unwrap(),
            CapturedOutcome::Exited(42)
        );
        assert_eq!(
            map_outcome(ExecOutcome::Signaled(9)).unwrap(),
            CapturedOutcome::Exited(137)
        );
        assert_eq!(
            map_outcome(ExecOutcome::TimedOut).unwrap(),
            CapturedOutcome::TimedOut
        );
    }

    #[test]
    fn rejects_non_terminal_success_outcomes() {
        assert!(map_outcome(ExecOutcome::Cancelled).is_err());
    }

    #[test]
    fn executor_adapter_preserves_exit_and_output() {
        for (expected_stdout, expected_stderr) in [
            (b"out".as_slice(), b"err".as_slice()),
            (b"\xff\0\xfe".as_slice(), b"\x80\0\x81".as_slice()),
            (b"".as_slice(), b"".as_slice()),
        ] {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let response = captured_to_script_response(
                CapturedRun {
                    outcome: CapturedOutcome::Exited(42),
                    warnings: Vec::new(),
                    stdout: expected_stdout.to_vec(),
                    stderr: expected_stderr.to_vec(),
                },
                &mut stdout,
                &mut stderr,
            )
            .unwrap();
            assert_eq!(response.exit_code, 42);
            assert_eq!(stdout, expected_stdout);
            assert_eq!(stderr, expected_stderr);
            assert!(response.standard_out.is_empty());
            assert!(response.standard_err.is_empty());
            assert!(response.error_message.is_empty());
        }
    }

    #[test]
    fn executor_adapter_marks_timeout() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let response = captured_to_script_response(
            CapturedRun {
                outcome: CapturedOutcome::TimedOut,
                warnings: Vec::new(),
                stdout: b"partial-out\xff".to_vec(),
                stderr: b"partial-err\x80".to_vec(),
            },
            &mut stdout,
            &mut stderr,
        )
        .unwrap();
        assert_eq!(response.exit_code, -1);
        assert_eq!(response.failure_phase, FailurePhase::Timeout);
        assert_eq!(response.error_message, "NVX workload timed out");
        assert_eq!(stdout, b"partial-out\xff");
        assert_eq!(stderr, b"partial-err\x80");
        assert!(response.standard_out.is_empty());
        assert!(response.standard_err.is_empty());
    }

    #[test]
    fn executor_adapter_surfaces_output_write_and_flush_failures() {
        struct FailingWriter {
            on_flush: bool,
        }

        impl Write for FailingWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self.on_flush {
                    Ok(bytes.len())
                } else {
                    Err(std::io::Error::other("test write failure"))
                }
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::other("test flush failure"))
            }
        }

        for on_flush in [false, true] {
            for stream in ["stdout", "stderr"] {
                let result = CapturedRun {
                    outcome: CapturedOutcome::Exited(0),
                    warnings: Vec::new(),
                    stdout: b"out".to_vec(),
                    stderr: b"err".to_vec(),
                };
                let mut failing = FailingWriter { on_flush };
                let mut sink = std::io::sink();
                let error = if stream == "stdout" {
                    captured_to_script_response(result, &mut failing, &mut sink)
                } else {
                    captured_to_script_response(result, &mut sink, &mut failing)
                }
                .unwrap_err();
                assert_eq!(error.code, MxcErrorCode::BackendError);
                let operation = if on_flush { "flush" } else { "write" };
                assert_eq!(
                    error.message,
                    format!("cannot relay NVX {stream}: test {operation} failure")
                );
            }
        }
    }

    #[test]
    fn cleanup_failure_is_not_success_and_preserves_primary_error() {
        let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);
        let cleanup = || vec![MxcError::backend_error("deprovision failed")];
        let success = finish_run(Ok(42), cleanup(), &mut logger).unwrap_err();
        assert!(success
            .message
            .contains("cleanup failed after workload completion"));

        let failure = finish_run::<()>(
            Err(MxcError::backend_unavailable("start failed")),
            cleanup(),
            &mut logger,
        )
        .unwrap_err();
        assert_eq!(failure.code, MxcErrorCode::BackendUnavailable);
        assert!(failure.message.contains("start failed"));
        assert!(failure.message.contains("deprovision failed"));
    }

    #[test]
    fn process_mapping_preserves_command_timeout_cwd_and_environment_presence() {
        let request = ExecutionRequest {
            script_code: "printf '%s' \"$KEY\"".to_owned(),
            working_directory: "/tmp".to_owned(),
            script_timeout: 250,
            env: Some(Vec::new()),
            inherit_default_env: true,
            ..Default::default()
        };
        let mapped = exec_request(&request);
        assert_eq!(
            mapped.process.command,
            aci_edge_sandboxes::Command::CommandLine(request.script_code)
        );
        assert_eq!(mapped.process.timeout, Some(Duration::from_millis(250)));
        assert_eq!(mapped.process.cwd.as_deref(), Some("/tmp"));
        assert_eq!(mapped.process.env, Some(Vec::new()));
        assert_eq!(mapped.process.inherit_default_env, Some(true));

        let defaults = exec_request(&ExecutionRequest::default());
        assert_eq!(defaults.process.env, None);
        assert_eq!(defaults.process.timeout, None);
        assert_eq!(defaults.process.cwd, None);
    }
}
