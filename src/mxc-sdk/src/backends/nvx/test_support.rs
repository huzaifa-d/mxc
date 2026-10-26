// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::io::{Read, Write};
use std::os::windows::io::IntoRawHandle;
use std::sync::{Arc, Mutex};

use super::abi::{Capabilities, ExecOutcome, ExecRequest, ImageSource, ProvisionInput};
use super::execution::ExecControl;
use super::runtime::{ExecOutput, Execution, SandboxClient, SandboxId};
use crate::mxc_common::mxc_error::MxcError;
use crate::mxc_common::process_util::{InterruptiblePipeReader, OwnedHandle, PipeReadCanceller};
use crate::mxc_common::sandbox_process::StreamCloser;
use windows::Win32::Foundation::HANDLE;

#[derive(Clone, Default)]
pub(super) struct Fixture {
    pub events: Arc<Mutex<Vec<&'static str>>>,
    pub fail: Option<&'static str>,
    pub stop_fails: bool,
    pub deprovision_fails: bool,
    pub outcome: Option<ExecOutcome>,
    pub capabilities: Option<Capabilities>,
    pub image: Arc<Mutex<Option<ImageSource>>>,
    pub stdin_piped: Arc<Mutex<Option<bool>>>,
    pub require_stdin_eof: bool,
    pub stdin_reader: Arc<Mutex<Option<InterruptiblePipeReader>>>,
    pub stdin_closer: Arc<Mutex<Option<PipeReadCanceller>>>,
    pub stop_gate: Option<Arc<CleanupGate>>,
}

#[derive(Debug, Default)]
pub(super) struct CleanupGate {
    pub entered: std::sync::atomic::AtomicBool,
    released: Mutex<bool>,
    wake: std::sync::Condvar,
}

impl CleanupGate {
    pub fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_all();
    }

    fn wait(&self) {
        self.entered
            .store(true, std::sync::atomic::Ordering::Release);
        let mut released = self.released.lock().unwrap();
        while !*released {
            released = self.wake.wait(released).unwrap();
        }
    }
}

impl Fixture {
    pub fn event(&self, stage: &'static str) -> Result<(), MxcError> {
        self.events.lock().unwrap().push(stage);
        if self.fail == Some(stage) {
            Err(MxcError::backend_error(format!(
                "NVX signed bundled agent: injected {stage} failure"
            )))
        } else {
            Ok(())
        }
    }

    pub fn id() -> SandboxId {
        SandboxId::from_token("0123456789abcdef0123456789abcdef").unwrap()
    }

    pub fn supported_capabilities() -> Capabilities {
        let mut capabilities = Capabilities::default();
        capabilities.exec.command_line = true;
        capabilities.exec.stdin = true;
        capabilities.exec.cancel = true;
        capabilities.exec.cwd = true;
        capabilities.exec.env = true;
        capabilities.exec.max_timeout_ms = Some(3_600_000);
        capabilities.spec.image_reference = true;
        capabilities
    }
}

impl SandboxClient for Fixture {
    fn capabilities(&self) -> Result<Capabilities, MxcError> {
        Ok(self
            .capabilities
            .clone()
            .unwrap_or_else(Self::supported_capabilities))
    }
    fn probe(&self) -> Result<(), MxcError> {
        self.event("probe")
    }
    fn validate_provision(&self, _input: &ProvisionInput) -> Result<(), MxcError> {
        self.event("validate_provision")
    }
    fn validate_exec(&self, _request: &ExecRequest) -> Result<(), MxcError> {
        self.event("validate_exec")
    }
    fn provision(&self, input: &ProvisionInput) -> Result<SandboxId, MxcError> {
        *self.image.lock().unwrap() = input.spec.image.clone();
        self.event("provision")?;
        Ok(Self::id())
    }
    fn start(&self, _id: &SandboxId) -> Result<(), MxcError> {
        self.event("start")
    }
    fn exec(&self, _id: &SandboxId, request: &ExecRequest) -> Result<Execution, MxcError> {
        self.validate_exec(request)?;
        *self.stdin_piped.lock().unwrap() = Some(request.stdin);
        self.event("exec")?;
        let (stdout, mut output) = std::io::pipe().unwrap();
        let (stderr, mut errors) = std::io::pipe().unwrap();
        output.write_all(b"out").unwrap();
        errors.write_all(b"err").unwrap();
        let stdin = if request.stdin {
            let (reader, writer) = std::io::pipe().unwrap();
            if self.require_stdin_eof {
                let reader = InterruptiblePipeReader::new(OwnedHandle::new(HANDLE(
                    reader.into_raw_handle(),
                )));
                *self.stdin_closer.lock().unwrap() = Some(reader.canceller());
                *self.stdin_reader.lock().unwrap() = Some(reader);
            }
            Some(writer)
        } else {
            None
        };
        Ok(Execution::new(
            Arc::new(self.clone()),
            stdin,
            stdout,
            stderr,
        ))
    }
    fn exec_and_wait(
        &self,
        _id: &SandboxId,
        _request: &ExecRequest,
    ) -> Result<ExecOutput, MxcError> {
        self.event("exec")?;
        Ok(ExecOutput {
            outcome: self.outcome.unwrap_or(ExecOutcome::Exited(7)),
            stdout: b"out".to_vec(),
            stderr: b"err".to_vec(),
        })
    }
    fn stop(&self, _id: &SandboxId) -> Result<(), MxcError> {
        self.event("stop")?;
        if let Some(gate) = &self.stop_gate {
            gate.wait();
        }
        if self.stop_fails {
            Err(MxcError::backend_error(
                "NVX signed bundled agent: injected stop failure",
            ))
        } else {
            Ok(())
        }
    }
    fn deprovision(&self, _id: &SandboxId) -> Result<(), MxcError> {
        self.event("deprovision")?;
        if self.deprovision_fails {
            Err(MxcError::backend_error(
                "NVX signed bundled agent: injected deprovision failure",
            ))
        } else {
            Ok(())
        }
    }
    fn close(&mut self) -> Result<(), MxcError> {
        Ok(())
    }
}

impl ExecControl for Fixture {
    fn wait(&self) -> Result<ExecOutcome, MxcError> {
        self.event("wait")?;
        if let Some(mut stdin) = self.stdin_reader.lock().unwrap().take() {
            let mut input = Vec::new();
            stdin
                .read_to_end(&mut input)
                .map_err(|error| MxcError::backend_error(format!("stdin read failed: {error}")))?;
        }
        Ok(self.outcome.unwrap_or(ExecOutcome::Exited(7)))
    }
    fn cancel(&self) -> Result<(), MxcError> {
        self.event("cancel")?;
        if let Some(closer) = self.stdin_closer.lock().unwrap().as_ref() {
            closer.close();
        }
        Ok(())
    }
}
