// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::io::Read;
use std::os::windows::io::{AsRawHandle, IntoRawHandle};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::WriteFile;
use windows::Win32::System::IO::CancelIoEx;

use crate::mxc_common::mxc_error::MxcError;
use crate::mxc_common::process_util::{InterruptiblePipeReader, OwnedHandle, PipeReadCanceller};
use crate::mxc_common::sandbox_process::StreamCloser;

use super::abi::{map_error_body, AgentLibrary, Event, ExecEnd, ExecOutcome, ExecRequest};

pub(super) trait ExecControl: Send + Sync {
    fn wait(&self) -> Result<ExecOutcome, MxcError>;
    fn cancel(&self) -> Result<(), MxcError>;
}

pub(super) struct Execution {
    control: Arc<dyn ExecControl>,
    stdin: Option<std::io::PipeWriter>,
    stdout: Option<std::io::PipeReader>,
    stderr: Option<std::io::PipeReader>,
    waited: bool,
}

impl Execution {
    pub fn new(
        control: Arc<dyn ExecControl>,
        stdin: Option<std::io::PipeWriter>,
        stdout: std::io::PipeReader,
        stderr: std::io::PipeReader,
    ) -> Self {
        Self {
            control,
            stdin,
            stdout: Some(stdout),
            stderr: Some(stderr),
            waited: false,
        }
    }

    pub fn take_stdin(&mut self) -> Option<std::io::PipeWriter> {
        self.stdin.take()
    }
    pub fn take_stdout(&mut self) -> Option<std::io::PipeReader> {
        self.stdout.take()
    }
    pub fn take_stderr(&mut self) -> Option<std::io::PipeReader> {
        self.stderr.take()
    }
    pub fn canceller(&self) -> Arc<dyn ExecControl> {
        Arc::clone(&self.control)
    }

    pub fn wait(mut self) -> Result<ExecOutcome, MxcError> {
        let result = self.control.wait();
        self.waited = true;
        result
    }
}

impl Drop for Execution {
    fn drop(&mut self) {
        if !self.waited {
            drop(self.stdin.take());
            drop(self.stdout.take());
            drop(self.stderr.take());
            if self.control.cancel().is_ok() {
                let _ = self.control.wait();
            }
        }
    }
}

#[derive(Default)]
struct WriteGate {
    cancelled: bool,
    writing: bool,
}

struct OutputPipe {
    pipe: Mutex<Option<Arc<std::io::PipeWriter>>>,
    gate: Mutex<WriteGate>,
}

impl OutputPipe {
    fn new(pipe: std::io::PipeWriter) -> Arc<Self> {
        Arc::new(Self {
            pipe: Mutex::new(Some(Arc::new(pipe))),
            gate: Mutex::new(WriteGate::default()),
        })
    }

    fn write_all(&self, mut bytes: &[u8]) -> std::io::Result<()> {
        let pipe = self
            .pipe
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let Some(pipe) = pipe else {
            return Ok(());
        };
        while !bytes.is_empty() {
            {
                let mut gate = self.gate.lock().unwrap_or_else(PoisonError::into_inner);
                if gate.cancelled {
                    return Ok(());
                }
                gate.writing = true;
            }
            let mut written = 0;
            // SAFETY: the owning pipe stays alive through this call and cancellation.
            let result = unsafe {
                WriteFile(
                    HANDLE(pipe.as_raw_handle()),
                    Some(bytes),
                    Some(&mut written),
                    None,
                )
            };
            let cancelled = {
                let mut gate = self.gate.lock().unwrap_or_else(PoisonError::into_inner);
                gate.writing = false;
                gate.cancelled
            };
            if cancelled {
                return Ok(());
            }
            result.map_err(std::io::Error::other)?;
            if written == 0 {
                return Err(std::io::ErrorKind::WriteZero.into());
            }
            bytes = &bytes[written as usize..];
        }
        Ok(())
    }

    fn close(&self) {
        self.gate
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .cancelled = true;
        let pipe = self
            .pipe
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let Some(pipe) = pipe else {
            return;
        };
        // CancelIoEx is edge-triggered: repeat until an announced write has returned.
        loop {
            unsafe {
                let _ = CancelIoEx(HANDLE(pipe.as_raw_handle()), None);
            }
            if !self
                .gate
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .writing
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn finish(&self) {
        self.pipe
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }
}

struct Shared {
    library: &'static AgentLibrary,
    handle: Mutex<Option<u64>>,
    stdin: Option<PipeReadCanceller>,
    stdout: Arc<OutputPipe>,
    stderr: Arc<OutputPipe>,
    finishing: AtomicBool,
    cancelled: AtomicBool,
    expired: AtomicBool,
    done: Mutex<bool>,
    wake: Condvar,
}

impl Shared {
    fn cancel(&self) -> Result<(), MxcError> {
        let result = {
            let handle = self.handle.lock().unwrap_or_else(PoisonError::into_inner);
            if self.cancelled.load(Ordering::Acquire) {
                return Ok(());
            }
            let result = match *handle {
                Some(handle) => self.library.exec_cancel(handle),
                None => Ok(()),
            };
            if result.is_ok() {
                self.cancelled.store(true, Ordering::Release);
                self.finishing.store(true, Ordering::Release);
            }
            result
        };
        if result.is_ok() {
            if let Some(stdin) = &self.stdin {
                stdin.close();
            }
            self.stdout.close();
            self.stderr.close();
        }
        result
    }
}

struct NativeControl {
    shared: Arc<Shared>,
    worker: Mutex<Option<JoinHandle<Result<ExecOutcome, MxcError>>>>,
    result: Mutex<Option<Result<ExecOutcome, MxcError>>>,
}

impl ExecControl for NativeControl {
    fn cancel(&self) -> Result<(), MxcError> {
        self.shared.cancel()
    }

    fn wait(&self) -> Result<ExecOutcome, MxcError> {
        let mut cached = self.result.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(result) = &*cached {
            return result.clone();
        }
        let worker = self
            .worker
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .ok_or_else(|| MxcError::backend_error("NVX execution worker is missing"))?;
        let result = worker
            .join()
            .unwrap_or_else(|_| Err(MxcError::backend_error("NVX execution worker panicked")));
        *cached = Some(result.clone());
        result
    }
}

fn io_error(error: std::io::Error) -> MxcError {
    MxcError::backend_error(format!("NVX streaming I/O failed: {error}"))
}

pub(super) fn launch(
    library: &'static AgentLibrary,
    handle: u64,
    request: &ExecRequest,
) -> Result<Execution, MxcError> {
    let prepared = (|| {
        let (stdout, output) = std::io::pipe().map_err(io_error)?;
        let (stderr, errors) = std::io::pipe().map_err(io_error)?;
        let (input, stdin) = if request.stdin {
            let (reader, writer) = std::io::pipe().map_err(io_error)?;
            let reader =
                InterruptiblePipeReader::new(OwnedHandle::new(HANDLE(reader.into_raw_handle())));
            (Some(reader), Some(writer))
        } else {
            (None, None)
        };
        Ok((stdout, output, stderr, errors, input, stdin))
    })();
    let (stdout, output, stderr, errors, input, stdin) = match prepared {
        Ok(streams) => streams,
        Err(mut error) => {
            append_error(&mut error, library.exec_cancel(handle));
            append_error(&mut error, library.exec_release(handle));
            return Err(error);
        }
    };
    let shared = Arc::new(Shared {
        library,
        handle: Mutex::new(Some(handle)),
        stdin: input.as_ref().map(InterruptiblePipeReader::canceller),
        stdout: OutputPipe::new(output),
        stderr: OutputPipe::new(errors),
        finishing: AtomicBool::new(false),
        cancelled: AtomicBool::new(false),
        expired: AtomicBool::new(false),
        done: Mutex::new(false),
        wake: Condvar::new(),
    });
    let deadline = request
        .process
        .timeout
        .filter(|&ms| ms != 0)
        .and_then(|ms| Instant::now().checked_add(Duration::from_millis(ms)));
    let pump = Arc::clone(&shared);
    let worker = match std::thread::Builder::new()
        .name("mxc-nvx-exec".into())
        .spawn(move || pump_execution(pump, handle, input, deadline))
    {
        Ok(worker) => worker,
        Err(error) => {
            let mut error = io_error(error);
            append_error(&mut error, shared.cancel());
            append_error(&mut error, library.exec_release(handle));
            return Err(error);
        }
    };
    let control = Arc::new(NativeControl {
        shared,
        worker: Mutex::new(Some(worker)),
        result: Mutex::new(None),
    });
    Ok(Execution::new(control, stdin, stdout, stderr))
}

fn append_error(primary: &mut MxcError, cleanup: Result<(), MxcError>) {
    if let Err(error) = cleanup {
        primary
            .message
            .push_str(&format!("; cleanup failure: {error}"));
    }
}

fn pump_execution(
    shared: Arc<Shared>,
    handle: u64,
    input: Option<InterruptiblePipeReader>,
    deadline: Option<Instant>,
) -> Result<ExecOutcome, MxcError> {
    let input_worker = input
        .map(|mut input| {
            let shared = Arc::clone(&shared);
            std::thread::Builder::new()
                .name("mxc-nvx-stdin".into())
                .spawn(move || {
                    let result = (|| {
                        let mut buffer = [0u8; 64 * 1024];
                        loop {
                            let read = input.read(&mut buffer).map_err(io_error)?;
                            if shared.finishing.load(Ordering::Acquire) {
                                return Ok(());
                            }
                            if read == 0 {
                                return shared.library.exec_close_input(handle);
                            }
                            let mut bytes = &buffer[..read];
                            while !bytes.is_empty() {
                                if shared.finishing.load(Ordering::Acquire) {
                                    return Ok(());
                                }
                                let written = shared.library.exec_write(handle, bytes)?;
                                bytes = &bytes[written..];
                            }
                        }
                    })();
                    if result.is_err() && !shared.finishing.load(Ordering::Acquire) {
                        let _ = shared.cancel();
                    }
                    result
                })
                .map_err(io_error)
        })
        .transpose();
    let input_worker = match input_worker {
        Ok(worker) => worker,
        Err(mut error) => {
            append_error(&mut error, shared.cancel());
            append_error(&mut error, shared.library.exec_release(handle));
            *shared.handle.lock().unwrap_or_else(PoisonError::into_inner) = None;
            return Err(error);
        }
    };
    let watchdog = deadline
        .map(|deadline| {
            let shared = Arc::clone(&shared);
            std::thread::Builder::new()
                .name("mxc-nvx-deadline".into())
                .spawn(move || {
                    let done = shared.done.lock().unwrap_or_else(PoisonError::into_inner);
                    let (done, _) = shared
                        .wake
                        .wait_timeout_while(
                            done,
                            deadline.saturating_duration_since(Instant::now()),
                            |done| !*done,
                        )
                        .unwrap_or_else(PoisonError::into_inner);
                    if !*done {
                        drop(done);
                        shared.expired.store(true, Ordering::Release);
                        shared.cancel()?;
                    }
                    Ok::<(), MxcError>(())
                })
                .map_err(io_error)
        })
        .transpose();
    let mut outcome = match &watchdog {
        Err(error) => Err(error.clone()),
        Ok(_) => loop {
            let event = shared
                .library
                .exec_next(handle, Some(100), |event| match event {
                    Event::Stdout(bytes) => {
                        let _ = shared.stdout.write_all(bytes);
                        Ok(None)
                    }
                    Event::Stderr(bytes) => {
                        let _ = shared.stderr.write_all(bytes);
                        Ok(None)
                    }
                    Event::Exit(bytes) => serde_json::from_slice::<ExecEnd>(bytes)
                        .map(Some)
                        .map_err(|error| {
                            MxcError::backend_error(format!("NVX malformed execution end: {error}"))
                        }),
                });
            match event {
                Ok(Some(Ok(Some(ExecEnd::Outcome(outcome))))) => break Ok(outcome),
                Ok(Some(Ok(Some(ExecEnd::Error(body))))) => break Err(map_error_body(body)),
                Ok(Some(Err(error))) | Err(error) => break Err(error),
                _ => {}
            }
        },
    };
    shared.finishing.store(true, Ordering::Release);
    shared.stdout.finish();
    shared.stderr.finish();
    *shared.done.lock().unwrap_or_else(PoisonError::into_inner) = true;
    shared.wake.notify_all();
    if outcome.is_err() {
        let _ = shared.cancel();
    }
    if let Some(stdin) = &shared.stdin {
        stdin.close();
    }
    if let Some(input) = input_worker {
        let result = input
            .join()
            .unwrap_or_else(|_| Err(MxcError::backend_error("NVX input worker panicked")));
        if let Err(error) = result {
            if outcome.is_ok() && !shared.expired.load(Ordering::Acquire) {
                outcome = Err(error);
            }
        }
    }
    if let Ok(Some(watchdog)) = watchdog {
        if let Err(error) = watchdog
            .join()
            .unwrap_or_else(|_| Err(MxcError::backend_error("NVX deadline worker panicked")))
        {
            if outcome.is_ok() {
                outcome = Err(error);
            }
        }
    }
    if shared.expired.load(Ordering::Acquire) && outcome.is_ok() {
        outcome = Ok(ExecOutcome::TimedOut);
    }
    let mut handle = shared.handle.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(handle) = handle.take() {
        if let Err(error) = shared.library.exec_release(handle) {
            match &mut outcome {
                Ok(_) => outcome = Err(error),
                Err(primary) => append_error(primary, Err(error)),
            }
        }
    }
    outcome
}
