// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Minimal one-shot adapter for the signed NVX agent runtime.

use std::io::{Read, Write};

use aci_edge_sandboxes::{AciEdgeSandbox, ExecOutcome, SandboxId};

use crate::mxc_common::logger::Logger;
use crate::mxc_common::models::{ExecutionRequest, FailurePhase, ScriptResponse};
use crate::mxc_common::mxc_error::{MxcError, MxcErrorCode};
use crate::mxc_common::sandbox_process::{NativeStdio, SandboxProcess, StreamCloser};
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
        validate_one_shot_lifecycle(request)?;
        super::policy::validate_common(request)?;
        let client = super::runtime::create_client()?;
        client.probe().map_err(super::runtime::map_nvx_error)?;
        let (provision, spec) =
            super::policy::provision_request(request, None, &client.capabilities())?;
        let exec = super::policy::exec_request(request, false, &client.capabilities())?;

        let provisioned = client
            .provision_with(&provision, &spec)
            .map_err(super::runtime::map_nvx_error)?;
        let sandbox_id = provisioned.sandbox_id;
        let primary = (|| {
            client
                .start(&sandbox_id)
                .map_err(super::runtime::map_nvx_error)?;
            client
                .exec(&sandbox_id, &exec)
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

    pub fn spawn_streaming(
        request: &ExecutionRequest,
    ) -> Result<Box<dyn SandboxProcess>, MxcError> {
        validate_one_shot_lifecycle(request)?;
        super::policy::validate_common(request)?;
        let client = super::runtime::create_client()?;
        let (provision, spec) =
            super::policy::provision_request(request, None, &client.capabilities())?;
        let provisioned = client
            .provision_with(&provision, &spec)
            .map_err(super::runtime::map_nvx_error)?;
        let sandbox_id = provisioned.sandbox_id;
        if let Err(error) = client.start(&sandbox_id) {
            let primary = super::runtime::map_nvx_error(error);
            let _ = client.deprovision(&sandbox_id);
            return Err(primary);
        }
        let exec = super::policy::exec_request(request, true, &client.capabilities())?;
        let execution = match client.exec(&sandbox_id, &exec) {
            Ok(execution) => execution,
            Err(error) => {
                let primary = super::runtime::map_nvx_error(error);
                let _ = client.stop(&sandbox_id);
                let _ = client.deprovision(&sandbox_id);
                return Err(primary);
            }
        };
        let handle = super::process::into_exec_handle(execution)?;
        let inner =
            match crate::mxc_common::exec_stream::ExecSandboxProcess::from_exec_handle(handle) {
                Ok(inner) => inner,
                Err(error) => {
                    let _ = client.stop(&sandbox_id);
                    let _ = client.deprovision(&sandbox_id);
                    return Err(error);
                }
            };
        Ok(Box::new(NvxOneShotProcess {
            inner: Box::new(inner),
            client,
            sandbox_id: Some(sandbox_id),
        }))
    }
}

struct NvxOneShotProcess {
    inner: Box<dyn SandboxProcess>,
    client: AciEdgeSandbox,
    sandbox_id: Option<SandboxId>,
}

impl NvxOneShotProcess {
    fn cleanup(&mut self) -> std::io::Result<()> {
        let Some(sandbox_id) = self.sandbox_id.take() else {
            return Ok(());
        };
        let stop = self.client.stop(&sandbox_id);
        let deprovision = self.client.deprovision(&sandbox_id);
        match (stop, deprovision) {
            (Ok(_), Ok(_)) => Ok(()),
            (stop, deprovision) => Err(std::io::Error::other(format!(
                "NVX cleanup failed: stop={:?}; deprovision={:?}",
                stop.err(),
                deprovision.err()
            ))),
        }
    }
}

impl SandboxProcess for NvxOneShotProcess {
    fn warnings(&self) -> Vec<String> {
        self.inner.warnings()
    }

    fn take_native_stdio(&mut self) -> std::io::Result<Option<NativeStdio>> {
        self.inner.take_native_stdio()
    }

    fn take_stdin(&mut self) -> Option<Box<dyn Write + Send>> {
        self.inner.take_stdin()
    }

    fn stdin_closer(&self) -> Option<Box<dyn StreamCloser>> {
        self.inner.stdin_closer()
    }

    fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>> {
        self.inner.take_stdout()
    }

    fn take_stderr(&mut self) -> Option<Box<dyn Read + Send>> {
        self.inner.take_stderr()
    }

    fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
        let result = self.inner.try_wait()?;
        if result.is_some() {
            self.cleanup()?;
        }
        Ok(result)
    }

    fn id(&self) -> u32 {
        self.inner.id()
    }

    fn kill(&mut self) -> std::io::Result<()> {
        self.inner.kill()
    }

    fn kill_for_timeout(&mut self) -> std::io::Result<()> {
        self.inner.kill_for_timeout()
    }

    fn wait(&mut self) -> std::io::Result<i32> {
        let result = self.inner.wait();
        let cleanup = self.cleanup();
        match (result, cleanup) {
            (Ok(code), Ok(())) => Ok(code),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }
}

impl Drop for NvxOneShotProcess {
    fn drop(&mut self) {
        if self.sandbox_id.is_some() {
            let _ = self.inner.kill();
            let _ = self.inner.wait();
            let _ = self.cleanup();
        }
    }
}

impl ScriptRunner for NvxRunner {
    fn validate_runner(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        validate_one_shot_lifecycle(request)
            .map_err(|error| ScriptResponse::rejected(&error.message))?;
        super::policy::validate_common(request)
            .map_err(|error| ScriptResponse::rejected(&error.message))?;
        let client = super::runtime::create_client()
            .map_err(|error| ScriptResponse::rejected(&error.message))?;
        super::policy::provision_request(request, None, &client.capabilities())
            .and_then(|_| super::policy::exec_request(request, false, &client.capabilities()))
            .map(|_| ())
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

fn validate_one_shot_lifecycle(request: &ExecutionRequest) -> Result<(), MxcError> {
    if !request.lifecycle.destroy_on_exit {
        return Err(MxcError::policy_validation(
            "NVX create-and-run requires lifecycle.destroyOnExit=true",
        ));
    }
    if request.lifecycle.preserve_policy {
        return Err(MxcError::policy_validation(
            "NVX create-and-run requires lifecycle.preservePolicy=false",
        ));
    }
    Ok(())
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

    #[test]
    fn create_and_run_rejects_non_default_lifecycle() {
        let mut request = ExecutionRequest::default();
        request.lifecycle.destroy_on_exit = false;
        assert!(validate_one_shot_lifecycle(&request)
            .unwrap_err()
            .message
            .contains("destroyOnExit=true"));
        request.lifecycle.destroy_on_exit = true;
        request.lifecycle.preserve_policy = true;
        assert!(validate_one_shot_lifecycle(&request)
            .unwrap_err()
            .message
            .contains("preservePolicy=false"));
    }
}
