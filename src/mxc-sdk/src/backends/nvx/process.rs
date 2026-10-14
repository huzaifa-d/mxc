// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::os::windows::io::AsRawHandle;
use std::sync::{Arc, Mutex, PoisonError};

use aci_edge_sandboxes::{ExecOutcome as NvxExecOutcome, Execution};
use windows::Win32::Foundation::HANDLE;

use crate::mxc_common::mxc_error::MxcError;
use crate::mxc_common::state_aware_backend::{ExecHandle, ExecOutcome};

struct LiveExecution {
    execution: Option<Execution>,
    stdin: Option<std::io::PipeWriter>,
    stdout: Option<std::io::PipeReader>,
    stderr: Option<std::io::PipeReader>,
}

pub(super) fn into_exec_handle(mut execution: Execution) -> Result<ExecHandle, MxcError> {
    let canceller = execution.canceller();
    let stdin = execution.take_stdin();
    let stdout = execution.take_stdout();
    let stderr = execution.take_stderr();
    let stdout_handle = pipe_reader_handle(stdout.as_ref());
    let stderr_handle = pipe_reader_handle(stderr.as_ref());
    let stdin_handle = pipe_writer_handle(stdin.as_ref());
    let shared = Arc::new(Mutex::new(LiveExecution {
        execution: Some(execution),
        stdin,
        stdout,
        stderr,
    }));
    let waiter_state = Arc::clone(&shared);
    let stdin_state = Arc::clone(&shared);

    Ok(ExecHandle {
        stdout: stdout_handle,
        stderr: stderr_handle,
        stdin: stdin_handle,
        waiter: Box::new(move || {
            let execution = waiter_state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .execution
                .take()
                .ok_or_else(|| MxcError::backend_error("NVX execution was already waited"))?;
            let outcome = execution
                .wait()
                .map_err(super::runtime::map_nvx_error)
                .and_then(map_outcome);
            let mut state = waiter_state.lock().unwrap_or_else(PoisonError::into_inner);
            state.stdin = None;
            state.stdout = None;
            state.stderr = None;
            outcome
        }),
        terminator: Box::new(move || canceller.cancel().map_err(super::runtime::map_nvx_error)),
        stdin_closer: Some(Box::new(move || {
            stdin_state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .stdin = None;
        })),
    })
}

fn pipe_reader_handle(reader: Option<&std::io::PipeReader>) -> HANDLE {
    reader.map_or_else(
        || HANDLE(std::ptr::null_mut()),
        |reader| HANDLE(reader.as_raw_handle()),
    )
}

fn pipe_writer_handle(writer: Option<&std::io::PipeWriter>) -> HANDLE {
    writer.map_or_else(
        || HANDLE(std::ptr::null_mut()),
        |writer| HANDLE(writer.as_raw_handle()),
    )
}

fn map_outcome(outcome: NvxExecOutcome) -> Result<ExecOutcome, MxcError> {
    match outcome {
        NvxExecOutcome::Exited(code) => Ok(ExecOutcome::Exited(code)),
        NvxExecOutcome::Signaled(signal) => Ok(ExecOutcome::Exited(128_i32.saturating_add(signal))),
        NvxExecOutcome::Cancelled => Ok(ExecOutcome::Exited(137)),
        NvxExecOutcome::TimedOut => Ok(ExecOutcome::TimedOut),
        other => Err(MxcError::backend_error(format!(
            "NVX workload did not complete normally: {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_terminal_outcomes() {
        assert_eq!(
            map_outcome(NvxExecOutcome::Exited(7)).unwrap(),
            ExecOutcome::Exited(7)
        );
        assert_eq!(
            map_outcome(NvxExecOutcome::Signaled(9)).unwrap(),
            ExecOutcome::Exited(137)
        );
        assert_eq!(
            map_outcome(NvxExecOutcome::Cancelled).unwrap(),
            ExecOutcome::Exited(137)
        );
        assert_eq!(
            map_outcome(NvxExecOutcome::TimedOut).unwrap(),
            ExecOutcome::TimedOut
        );
    }
}
