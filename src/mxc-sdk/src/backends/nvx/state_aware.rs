// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::abi::ProvisionInput;
use super::runtime::{SandboxClient, SandboxId};
use serde_json::Value;

use crate::mxc_common::models::{ExecutionRequest, MicroVmProvisionConfig};
use crate::mxc_common::mxc_error::MxcError;
use crate::mxc_common::sandbox_process::SandboxProcess;
use crate::mxc_common::state_aware_backend::{
    DeprovisionResult, ExecHandle, ExecStdio, ProvisionResult, StartResult, StatefulSandboxBackend,
    StopResult,
};

pub struct NvxStateAwareRunner {
    client: Box<dyn SandboxClient + Send>,
    provisioned_id: Option<String>,
}

impl NvxStateAwareRunner {
    pub fn new() -> Result<Self, MxcError> {
        let state_root = super::runtime::lifecycle_state_root()?;
        Ok(Self {
            client: Box::new(super::runtime::create_client(&state_root)?),
            provisioned_id: None,
        })
    }

    pub(crate) fn complete<T>(mut self, result: Result<T, MxcError>) -> Result<T, MxcError> {
        let mut close = self.client.close();
        if let (Err(error), Some(id)) = (&mut close, &self.provisioned_id) {
            error.message.push_str(&format!(
                "; provisioned sandbox {id} remains available for stop/deprovision"
            ));
        }
        match (result, close) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(mut primary), Err(cleanup)) => {
                primary
                    .message
                    .push_str(&format!("; host cleanup failure: {cleanup}"));
                Err(primary)
            }
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        }
    }

    pub(crate) fn complete_streaming(
        self,
        result: Result<Box<dyn SandboxProcess>, MxcError>,
    ) -> Result<Box<dyn SandboxProcess>, MxcError> {
        match result {
            Err(error) => self.complete(Err(error)),
            Ok(process) => {
                let mut client = self.client;
                Ok(Box::new(super::runner::NvxOwnedProcess::new(
                    process,
                    Box::new(move || {
                        client.close().map_err(|error| {
                            std::io::Error::other(format!("NVX host cleanup failed: {error}"))
                        })
                    }),
                )))
            }
        }
    }
}

impl StatefulSandboxBackend for NvxStateAwareRunner {
    const ID_PREFIX: &'static str = "microvm";
    const BACKEND_KEY: &'static str = "microvm";

    type ProvisionConfig = MicroVmProvisionConfig;
    type StartConfig = ();
    type ExecConfig = ();
    type StopConfig = ();
    type DeprovisionConfig = ();
    type ProvisionMetadata = Value;
    type StartMetadata = ();
    type StopMetadata = ();
    type DeprovisionMetadata = ();

    fn provision(
        &mut self,
        request: &ExecutionRequest,
        config: Option<Self::ProvisionConfig>,
    ) -> Result<ProvisionResult<Self::ProvisionMetadata>, MxcError> {
        let (provision, spec) = super::policy::provision_request(
            request,
            config.as_ref(),
            &self.client.capabilities()?,
        )?;
        let input = ProvisionInput {
            request: provision,
            spec,
        };
        self.client.validate_provision(&input)?;
        self.client.probe()?;
        let (id, metadata) = self.client.provision_metadata(&input)?;
        self.provisioned_id = Some(mxc_id(&id));
        Ok(ProvisionResult {
            sandbox_id: mxc_id(&id),
            metadata,
        })
    }

    fn start(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<Self::StartConfig>,
    ) -> Result<StartResult<Self::StartMetadata>, MxcError> {
        self.client.start(&native_id(sandbox_id)?)?;
        Ok(StartResult { metadata: None })
    }

    fn exec(
        &mut self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<Self::ExecConfig>,
        stdio: ExecStdio,
    ) -> Result<ExecHandle, MxcError> {
        let piped = stdio == ExecStdio::Piped;
        let request = super::policy::exec_request(request, piped, &self.client.capabilities()?)?;
        let execution = self.client.exec(&native_id(sandbox_id)?, &request)?;
        super::process::into_exec_handle(execution, stdio)
    }

    fn stop(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<Self::StopConfig>,
    ) -> Result<StopResult<Self::StopMetadata>, MxcError> {
        self.client.stop(&native_id(sandbox_id)?)?;
        Ok(StopResult { metadata: None })
    }

    fn deprovision(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<Self::DeprovisionConfig>,
    ) -> Result<DeprovisionResult<Self::DeprovisionMetadata>, MxcError> {
        self.client.deprovision(&native_id(sandbox_id)?)?;
        Ok(DeprovisionResult { metadata: None })
    }

    fn validate_provision(
        &self,
        request: &ExecutionRequest,
        config: Option<&Self::ProvisionConfig>,
    ) -> Result<(), MxcError> {
        let (provision, spec) =
            super::policy::provision_request(request, config, &self.client.capabilities()?)?;
        self.client.validate_provision(&ProvisionInput {
            request: provision,
            spec,
        })
    }

    fn validate_start(
        &self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<&Self::StartConfig>,
    ) -> Result<(), MxcError> {
        native_id(sandbox_id).map(|_| ())
    }

    fn validate_exec(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&Self::ExecConfig>,
    ) -> Result<(), MxcError> {
        native_id(sandbox_id)?;
        let request = super::policy::exec_request(request, false, &self.client.capabilities()?)?;
        self.client.validate_exec(&request)
    }

    fn validate_stop(
        &self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<&Self::StopConfig>,
    ) -> Result<(), MxcError> {
        native_id(sandbox_id).map(|_| ())
    }

    fn validate_deprovision(
        &self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<&Self::DeprovisionConfig>,
    ) -> Result<(), MxcError> {
        native_id(sandbox_id).map(|_| ())
    }
}

fn native_id(value: &str) -> Result<SandboxId, MxcError> {
    let token = value
        .strip_prefix("microvm:")
        .ok_or_else(|| MxcError::malformed_id("MicroVM sandbox ID must start with 'microvm:'"))?;
    SandboxId::from_token(token).map_err(|_| {
        MxcError::malformed_id("MicroVM sandbox ID requires 32 lowercase hexadecimal digits")
    })
}

fn mxc_id(value: &SandboxId) -> String {
    format!("microvm:{}", value.token())
}

#[cfg(test)]
mod tests {
    use super::super::abi::ExecOutcome as NvxExecOutcome;
    use super::super::test_support::Fixture;
    use super::*;
    use crate::mxc_common::state_aware_backend::ExecOutcome;
    use crate::mxc_common::state_aware_binding::{
        BoundStateAwareOperation, BoundStateAwareRequest,
    };
    use crate::mxc_common::state_aware_dispatch::{
        dispatch_state_aware_exec, dispatch_state_aware_typed, TypedDispatchOutcome,
    };

    fn bound_exec() -> BoundStateAwareRequest<NvxStateAwareRunner> {
        BoundStateAwareRequest::for_test(
            ExecutionRequest {
                script_code: "printf test".to_owned(),
                script_timeout: 1_000,
                inherit_default_env: true,
                ..Default::default()
            },
            BoundStateAwareOperation::Exec {
                sandbox_id: mxc_id(&Fixture::id()),
                config: None,
            },
        )
    }

    #[test]
    fn relayed_dispatch_reports_nvx_timeout_not_a_protocol_violation() {
        for outcome in [NvxExecOutcome::Exited(7), NvxExecOutcome::TimedOut] {
            let fixture = Fixture {
                outcome: Some(outcome),
                ..Default::default()
            };
            let mut backend = NvxStateAwareRunner {
                client: Box::new(fixture.clone()),
                provisioned_id: None,
            };
            let result = dispatch_state_aware_typed(&mut backend, bound_exec(), false);
            if outcome == NvxExecOutcome::TimedOut {
                let error = result.unwrap_err();
                assert_eq!(
                    error.code,
                    crate::mxc_common::mxc_error::MxcErrorCode::BackendError
                );
                assert_eq!(
                    error.message,
                    "NVX relayed exec timed out; workload deadline elapsed"
                );
            } else {
                assert!(matches!(
                    result.unwrap(),
                    TypedDispatchOutcome::ExecCompleted { exit_code: 7 }
                ));
            }
            assert_eq!(*fixture.stdin_piped.lock().unwrap(), Some(false));
            let mut events = vec!["validate_exec", "validate_exec", "exec", "wait"];
            if outcome == NvxExecOutcome::TimedOut {
                events.push("cancel");
            }
            assert_eq!(*fixture.events.lock().unwrap(), events);
        }
    }

    #[test]
    fn piped_dispatch_retains_exit_timeout_and_real_stream_contracts() {
        for outcome in [NvxExecOutcome::Exited(7), NvxExecOutcome::TimedOut] {
            let fixture = Fixture {
                outcome: Some(outcome),
                ..Default::default()
            };
            let mut backend = NvxStateAwareRunner {
                client: Box::new(fixture.clone()),
                provisioned_id: None,
            };
            let handle = dispatch_state_aware_exec(&mut backend, bound_exec()).unwrap();
            assert!(!handle.stdin.0.is_null());
            assert!(!handle.stdout.0.is_null());
            assert!(!handle.stderr.0.is_null());
            assert!(handle.stdin_closer.is_some());
            // The real adapter, not the outcome helper, owns these pipes and waiter.
            let actual = (handle.waiter)().unwrap();
            assert_eq!(
                actual,
                if outcome == NvxExecOutcome::TimedOut {
                    ExecOutcome::TimedOut
                } else {
                    ExecOutcome::Exited(7)
                }
            );
            assert_eq!(*fixture.stdin_piped.lock().unwrap(), Some(true));
            assert_eq!(
                *fixture.events.lock().unwrap(),
                ["validate_exec", "validate_exec", "exec", "wait"]
            );
        }
    }

    #[test]
    fn ids_translate_without_exposing_native_prefix() {
        let native = SandboxId::from_token("0123456789abcdef0123456789abcdef").unwrap();
        let mxc = mxc_id(&native);
        assert_eq!(mxc, "microvm:0123456789abcdef0123456789abcdef");
        assert_eq!(native_id(&mxc).unwrap(), native);
    }

    #[test]
    fn malformed_mxc_ids_are_rejected() {
        assert!(native_id("aci-edge-sandboxes:0123456789abcdef0123456789abcdef").is_err());
        assert!(native_id("microvm:bad").is_err());
    }

    fn fixture_backend(fixture: &Fixture) -> NvxStateAwareRunner {
        NvxStateAwareRunner {
            client: Box::new(fixture.clone()),
            provisioned_id: None,
        }
    }

    fn bound_stop() -> BoundStateAwareRequest<NvxStateAwareRunner> {
        BoundStateAwareRequest::for_test(
            ExecutionRequest::default(),
            BoundStateAwareOperation::Stop {
                sandbox_id: mxc_id(&Fixture::id()),
                config: None,
            },
        )
    }

    #[test]
    fn review_lifecycle_dispatch_combines_host_close_on_success_and_failure() {
        for typed in [false, true] {
            for failed in [false, true] {
                let fixture = Fixture {
                    fail: failed.then_some("stop"),
                    close_fails: true,
                    ..Default::default()
                };
                let mut backend = fixture_backend(&fixture);
                let result = if typed {
                    dispatch_state_aware_typed(&mut backend, bound_stop(), false).map(|_| ())
                } else {
                    crate::mxc_common::state_aware_dispatch::dispatch_state_aware(
                        &mut backend,
                        bound_stop(),
                        false,
                    )
                    .map(|_| ())
                };
                assert_eq!(result.is_err(), failed);
                let error = backend.complete(result).unwrap_err();
                assert_eq!(
                    error.code,
                    crate::mxc_common::mxc_error::MxcErrorCode::BackendError
                );
                assert!(
                    error.message.contains("injected host_close failure"),
                    "{error}"
                );
                if failed {
                    assert!(
                        error
                            .message
                            .starts_with("NVX signed bundled agent: injected stop failure"),
                        "{error}"
                    );
                }
                assert_eq!(
                    fixture
                        .close_calls
                        .load(std::sync::atomic::Ordering::Acquire),
                    1
                );
            }
        }
    }

    #[test]
    fn review_failed_host_close_retains_newly_provisioned_identity() {
        let fixture = Fixture {
            close_fails: true,
            ..Default::default()
        };
        let mut backend = fixture_backend(&fixture);
        let bound = BoundStateAwareRequest::for_test(
            ExecutionRequest {
                microvm_image: Some("python:3.12-alpine".to_owned()),
                ..Default::default()
            },
            BoundStateAwareOperation::Provision(None),
        );
        let result = dispatch_state_aware_typed(&mut backend, bound, false);
        assert!(result.is_ok());
        let error = backend.complete(result).unwrap_err();
        assert!(
            error.message.contains("injected host_close failure"),
            "{error}"
        );
        assert!(
            error.message.contains(&format!(
                "sandbox {} remains available for stop/deprovision",
                mxc_id(&Fixture::id())
            )),
            "{error}"
        );
        assert_eq!(
            fixture
                .close_calls
                .load(std::sync::atomic::Ordering::Acquire),
            1
        );
    }

    #[test]
    fn review_host_close_preserves_validation_error_precedence() {
        let fixture = Fixture {
            close_fails: true,
            ..Default::default()
        };
        let mut backend = fixture_backend(&fixture);
        let bound = BoundStateAwareRequest::for_test(
            ExecutionRequest::default(),
            BoundStateAwareOperation::Stop {
                sandbox_id: "microvm:bad".to_owned(),
                config: None,
            },
        );
        let result = dispatch_state_aware_typed(&mut backend, bound, false);
        let error = backend.complete(result).unwrap_err();
        assert_eq!(
            error.code,
            crate::mxc_common::mxc_error::MxcErrorCode::MalformedId
        );
        assert!(
            error
                .message
                .starts_with("MicroVM sandbox ID requires 32 lowercase hexadecimal digits"),
            "{error}"
        );
        assert!(
            error.message.contains("injected host_close failure"),
            "{error}"
        );
        assert!(
            fixture.events.lock().unwrap().is_empty(),
            "validation failure called native stop"
        );
        assert_eq!(
            fixture
                .close_calls
                .load(std::sync::atomic::Ordering::Acquire),
            1
        );
    }

    fn dispatch_stream(fixture: &Fixture) -> Result<Box<dyn SandboxProcess>, MxcError> {
        let mut backend = fixture_backend(fixture);
        let handle = dispatch_state_aware_exec(&mut backend, bound_exec());
        let process = handle.and_then(|handle| {
            crate::mxc_common::exec_stream::ExecSandboxProcess::from_exec_handle(handle)
                .map(|process| Box::new(process) as Box<dyn SandboxProcess>)
        });
        backend.complete_streaming(process)
    }

    #[test]
    fn review_live_exec_retains_fallible_host_close_until_wait() {
        for failed in [false, true] {
            let fixture = Fixture {
                fail: failed.then_some("wait"),
                close_fails: true,
                ..Default::default()
            };
            let process = dispatch_stream(&fixture).unwrap();
            assert_eq!(
                fixture
                    .close_calls
                    .load(std::sync::atomic::Ordering::Acquire),
                0
            );
            let error = crate::sandbox::MxcProcess::new(process)
                .wait_with_output()
                .unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::Other);
            assert!(
                error.to_string().contains("injected host_close failure"),
                "{error}"
            );
            if failed {
                assert!(
                    error.to_string().contains("injected wait failure"),
                    "{error}"
                );
            }
            assert_eq!(
                fixture
                    .close_calls
                    .load(std::sync::atomic::Ordering::Acquire),
                1
            );
        }
        let fixture = Fixture {
            fail: Some("exec"),
            close_fails: true,
            ..Default::default()
        };
        let error = dispatch_stream(&fixture).err().unwrap();
        assert!(error.message.contains("injected exec failure"), "{error}");
        assert!(
            error.message.contains("injected host_close failure"),
            "{error}"
        );
        assert_eq!(
            fixture
                .close_calls
                .load(std::sync::atomic::Ordering::Acquire),
            1
        );
    }

    #[test]
    fn review_live_host_close_does_not_block_poll() {
        use std::sync::atomic::Ordering;
        use std::time::{Duration, Instant};
        let gate = std::sync::Arc::new(super::super::test_support::CleanupGate::default());
        let fixture = Fixture {
            close_gate: Some(std::sync::Arc::clone(&gate)),
            ..Default::default()
        };
        let mut process = dispatch_stream(&fixture).unwrap();
        let worker_gate = std::sync::Arc::clone(&gate);
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            while !worker_gate.entered.load(Ordering::Acquire) && Instant::now() < deadline {
                assert!(process.try_wait().unwrap().is_none());
                std::thread::yield_now();
            }
            let polls = (0..5).map(|_| process.try_wait()).collect::<Vec<_>>();
            tx.send((polls, process)).unwrap();
        });
        let result = rx.recv_timeout(Duration::from_secs(2));
        let prompt = result.is_ok();
        gate.release();
        let (polls, mut process) =
            result.unwrap_or_else(|_| rx.recv_timeout(Duration::from_secs(2)).unwrap());
        worker.join().unwrap();
        assert!(prompt, "poll waited for host_close");
        assert!(polls.into_iter().all(|poll| matches!(poll, Ok(None))));
        assert_eq!(process.wait().unwrap(), 7);
        assert_eq!(fixture.close_calls.load(Ordering::Acquire), 1);
    }
}
