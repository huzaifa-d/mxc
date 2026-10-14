// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Minimal one-shot adapter for the signed NVX agent runtime.

use std::time::Duration;

use aci_edge_sandboxes::{ExecOutcome, ExecRequest, ProvisionRequest};

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
        super::policy::validate_phase_one(request)?;
        let client = super::runtime::create_client()?;
        client.probe().map_err(super::runtime::map_nvx_error)?;

        let provisioned = client
            .provision(&ProvisionRequest::new())
            .map_err(super::runtime::map_nvx_error)?;
        let sandbox_id = provisioned.sandbox_id;
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
        let cleanup_errors: Vec<MxcError> = [
            stop_error,
            client
                .deprovision(&sandbox_id)
                .err()
                .map(super::runtime::map_nvx_error),
        ]
        .into_iter()
        .flatten()
        .collect();

        let output = match primary {
            Ok(output) if cleanup_errors.is_empty() => output,
            Ok(_) => {
                return Err(MxcError::backend_error(format!(
                    "NVX cleanup failed after workload completion: {}",
                    cleanup_errors
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("; ")
                )));
            }
            Err(mut error) => {
                for cleanup in cleanup_errors {
                    let warning = format!("NVX cleanup failed: {cleanup}");
                    logger.warning_line(&warning);
                    error.message.push_str("; cleanup failure: ");
                    error.message.push_str(&cleanup.to_string());
                }
                return Err(error);
            }
        };

        Ok(CapturedRun {
            outcome: map_outcome(output.outcome)?,
            warnings: Vec::new(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

impl ScriptRunner for NvxRunner {
    fn validate_runner(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        super::policy::validate_phase_one(request)
            .map_err(|error| ScriptResponse::rejected(&error.message))
    }

    fn execute(&mut self, request: &ExecutionRequest, logger: &mut Logger) -> ScriptResponse {
        match self.run_captured(request, logger) {
            Ok(result) => captured_to_script_response(result),
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

fn captured_to_script_response(result: CapturedRun) -> ScriptResponse {
    let standard_out = String::from_utf8_lossy(&result.stdout).into_owned();
    let standard_err = String::from_utf8_lossy(&result.stderr).into_owned();
    match result.outcome {
        CapturedOutcome::Exited(exit_code) => ScriptResponse {
            exit_code,
            standard_out,
            standard_err,
            ..Default::default()
        },
        CapturedOutcome::TimedOut => ScriptResponse {
            exit_code: -1,
            standard_out,
            standard_err,
            error_message: "NVX workload timed out".to_string(),
            failure_phase: FailurePhase::Timeout,
            ..Default::default()
        },
    }
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
        let response = captured_to_script_response(CapturedRun {
            outcome: CapturedOutcome::Exited(42),
            warnings: Vec::new(),
            stdout: b"out".to_vec(),
            stderr: b"err".to_vec(),
        });
        assert_eq!(response.exit_code, 42);
        assert_eq!(response.standard_out, "out");
        assert_eq!(response.standard_err, "err");
        assert!(response.error_message.is_empty());
    }

    #[test]
    fn executor_adapter_marks_timeout() {
        let response = captured_to_script_response(CapturedRun {
            outcome: CapturedOutcome::TimedOut,
            warnings: Vec::new(),
            stdout: Vec::new(),
            stderr: Vec::new(),
        });
        assert_eq!(response.exit_code, -1);
        assert_eq!(response.failure_phase, FailurePhase::Timeout);
    }
}
