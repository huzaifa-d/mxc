// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::env;
use std::ffi::OsString;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::mxc_common::mxc_error::MxcError;

use super::abi::{
    map_error_body, AgentLibrary, BundleSource, Capabilities, Event, ExecEnd, ExecInput,
    ExecOutcome, ExecRequest, HostInfo, ImageSource, ProvisionInput, RuntimeSource, SandboxSpec,
    SetupConfig,
};
pub(super) use super::execution::Execution;

pub(super) const ARTIFACTS_DIR_ENV: &str = "ACI_EDGE_SANDBOXES_AGENT_ARTIFACTS_DIR";
pub(super) const BESIDE_EXE_DIR: &str = "aci-edge-sandboxes";
pub(super) const SOURCE_MANIFEST: &str = "SOURCE-MANIFEST.json";

pub(super) const APPROVED_MANIFEST_SHA256: &str =
    "d5487737b07d663d983373dec82d917bbfcab58e39fed45b6642e8885c3fb01b";
pub(super) const APPROVED_DLL_SHA256: &str =
    "a203e58b97a642bd4a68824c0387965541895b25582e18db6f55e28947f5f135";
pub(super) const APPROVED_OPENVMM_SHA256: &str =
    "697f8221e62a1ea4efb3846fefde6f595c89f4f81c0153a2609bf6fb4c81ea9e";
const APPROVED_IMAGE_TOOL_SHA256: &str =
    "633b679a8f8f2586626b7475b1e5e3faa3d2ea7119082ffc5873191194feb6fe";
pub(super) const APPROVED_KERNEL_SHA256: &str =
    "b36ab45b22d1c14438047b24c3724f54cc71dd03601d0f3cbdca11438f40e768";
pub(super) const APPROVED_INITRD_SHA256: &str =
    "5e42d4617c1508e9116df8c330c0ff72243e954d7f132091ecdecfc743d904ed";

const HOST_TIMEOUT_SLACK_MS: u64 = 30_000;
const CAPTURE_LIMIT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SandboxId {
    full: String,
}

impl SandboxId {
    const PREFIX: &'static str = "aci-edge-sandboxes";
    const TOKEN_LEN: usize = 32;

    pub fn from_token(token: &str) -> Result<Self, MxcError> {
        if token.len() != Self::TOKEN_LEN
            || !token
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(MxcError::backend_error(
                "NVX signed bundled agent: the agent library returned a malformed sandbox token",
            ));
        }
        Ok(Self {
            full: format!("{}:{token}", Self::PREFIX),
        })
    }

    pub fn token(&self) -> &str {
        &self.full[Self::PREFIX.len() + 1..]
    }
}

impl fmt::Display for SandboxId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.full)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExecOutput {
    pub outcome: ExecOutcome,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub(super) trait SandboxClient {
    fn capabilities(&self) -> Result<Capabilities, MxcError>;
    fn validate_provision(&self, input: &ProvisionInput) -> Result<(), MxcError>;
    fn validate_exec(&self, request: &ExecRequest) -> Result<(), MxcError>;
    fn probe(&self) -> Result<(), MxcError>;
    fn provision(&self, input: &ProvisionInput) -> Result<SandboxId, MxcError>;
    fn start(&self, sandbox_id: &SandboxId) -> Result<(), MxcError>;
    fn exec(&self, _sandbox_id: &SandboxId, _request: &ExecRequest) -> Result<Execution, MxcError> {
        Err(MxcError::backend_error(
            "NVX client does not implement streaming",
        ))
    }
    fn provision_metadata(
        &self,
        input: &ProvisionInput,
    ) -> Result<(SandboxId, Option<serde_json::Value>), MxcError> {
        self.provision(input).map(|id| (id, None))
    }
    fn exec_and_wait(
        &self,
        sandbox_id: &SandboxId,
        request: &ExecRequest,
    ) -> Result<ExecOutput, MxcError>;
    fn stop(&self, sandbox_id: &SandboxId) -> Result<(), MxcError>;
    fn deprovision(&self, sandbox_id: &SandboxId) -> Result<(), MxcError>;
    fn close(&mut self) -> Result<(), MxcError>;
}

#[derive(Debug)]
pub(super) struct NvxClient {
    library: &'static AgentLibrary,
    host: u64,
    closed: bool,
}

impl NvxClient {
    pub(super) fn from_library(library: &'static AgentLibrary, host: u64) -> Self {
        Self {
            library,
            host,
            closed: false,
        }
    }
}

impl Drop for NvxClient {
    fn drop(&mut self) {
        if !self.closed {
            self.closed = true;
            let _ = self.library.host_close(self.host);
        }
    }
}

pub(super) fn create_client(state_root: &Path) -> Result<NvxClient, MxcError> {
    let bundle_dir = discover_bundle_dir()?;
    let library = load_bundle_library(&bundle_dir)?;
    let setup = SetupConfig {
        schema_version: 1,
        state_root: state_root.to_path_buf(),
        runtime: RuntimeSource {
            bundle: BundleSource {
                path: bundle_dir,
                manifest_sha256: APPROVED_MANIFEST_SHA256.to_owned(),
            },
        },
    };
    let host = library.host_open(&setup)?;
    let mut client = NvxClient::from_library(library, host);
    let info = match client.library.host_info(client.host) {
        Ok(info) => info,
        Err(mut error) => {
            if let Err(close_error) = client.close() {
                error.message.push_str("; cleanup failure: ");
                error.message.push_str(&close_error.to_string());
            }
            return Err(error);
        }
    };
    if let Err(mut error) = verify_runtime_digests(&info) {
        if let Err(close_error) = client.close() {
            error.message.push_str("; cleanup failure: ");
            error.message.push_str(&close_error.to_string());
        }
        return Err(error);
    }
    Ok(client)
}

fn verify_runtime_digests(info: &HostInfo) -> Result<(), MxcError> {
    for (name, actual, expected) in [
        (
            "openvmm",
            &info.runtime_digests.openvmm,
            APPROVED_OPENVMM_SHA256,
        ),
        (
            "kernel",
            &info.runtime_digests.kernel,
            APPROVED_KERNEL_SHA256,
        ),
        (
            "initrd",
            &info.runtime_digests.initrd,
            APPROVED_INITRD_SHA256,
        ),
    ] {
        if !actual.eq_ignore_ascii_case(expected) {
            return Err(MxcError::backend_unavailable(format!(
                "NVX signed bundled agent: runtime digest mismatch for {name}: expected {expected}, got {actual}"
            )));
        }
    }
    Ok(())
}

pub(super) fn lifecycle_state_root() -> Result<PathBuf, MxcError> {
    let local_app_data = std::env::var_os("LOCALAPPDATA").ok_or_else(|| {
        MxcError::backend_unavailable(
            "cannot resolve LOCALAPPDATA for the persistent NVX lifecycle state",
        )
    })?;
    let state_root = PathBuf::from(local_app_data)
        .join("Microsoft")
        .join("MXC")
        .join("nvx");
    admit_persistent_state_root(&state_root)?;
    Ok(state_root)
}

fn admit_persistent_state_root(state_root: &Path) -> Result<(), MxcError> {
    let parent = state_root.parent().ok_or_else(|| {
        MxcError::backend_unavailable("persistent NVX lifecycle state path has no parent")
    })?;
    std::fs::create_dir_all(parent).map_err(|error| {
        MxcError::backend_unavailable(format!(
            "cannot create the persistent NVX lifecycle state parent '{}': {error}",
            parent.display()
        ))
    })?;

    match crate::mxc_common::filesystem_dacl::create_owner_only_directory(state_root, true)
        .map_err(|error| {
            MxcError::backend_unavailable(format!(
                "cannot create persistent NVX lifecycle state root '{}': {error}",
                state_root.display()
            ))
        })? {
        crate::mxc_common::filesystem_dacl::CreateDirectoryDisposition::Created => {
            if let Err(error) = validate_private_state_root(state_root, "new ") {
                let _ = std::fs::remove_dir(state_root);
                return Err(error);
            }
        }
        crate::mxc_common::filesystem_dacl::CreateDirectoryDisposition::AlreadyExists => {
            validate_private_state_root(state_root, "")?;
        }
    }
    Ok(())
}

fn validate_private_state_root(state_root: &Path, prefix: &str) -> Result<(), MxcError> {
    let metadata = std::fs::symlink_metadata(state_root).map_err(|error| {
        MxcError::backend_unavailable(format!(
            "cannot inspect {prefix}persistent NVX lifecycle state root '{}': {error}",
            state_root.display()
        ))
    })?;
    if !metadata.is_dir() || is_reparse_point(&metadata) {
        return Err(MxcError::backend_unavailable(format!(
            "refusing {prefix}persistent NVX lifecycle state root '{}': expected a directory without a reparse point",
            state_root.display()
        )));
    }
    let secure = crate::mxc_common::filesystem_dacl::validate_owner_only_directory(state_root)
        .map_err(|error| {
            MxcError::backend_unavailable(format!(
                "cannot validate {prefix}persistent NVX lifecycle state root '{}': {error}",
                state_root.display()
            ))
        })?;
    if !secure {
        return Err(MxcError::backend_unavailable(format!(
            "refusing {prefix}persistent NVX lifecycle state root '{}': owner or ACL is not private",
            state_root.display()
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT.0
        != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}

pub(super) fn sandbox_spec(image: &str) -> Result<SandboxSpec, MxcError> {
    crate::mxc_contract::dev::ImageReference::validate(image)
        .map_err(MxcError::malformed_request)?;
    Ok(SandboxSpec {
        image: Some(ImageSource::Reference(image.to_owned())),
        ..Default::default()
    })
}

fn discover_bundle_dir() -> Result<PathBuf, MxcError> {
    let discovered = discover_bundle_with(|name| env::var_os(name), env::current_exe)?;
    std::path::absolute(&discovered).map_err(|error| {
        MxcError::backend_unavailable(format!(
            "NVX signed bundled agent: cannot resolve the agent bundle directory {}: {error}",
            discovered.display()
        ))
    })
}

pub(super) fn bundle_available() -> bool {
    discover_bundle_dir()
        .and_then(|directory| load_bundle_library(&directory))
        .is_ok()
}

fn load_bundle_library(directory: &Path) -> Result<&'static AgentLibrary, MxcError> {
    if !directory.join("bundle-manifest.json").is_file() {
        return Err(MxcError::backend_unavailable(format!(
            "NVX signed bundled agent: missing bundle-manifest.json in {}",
            directory.display()
        )));
    }
    for (path, expected) in [
        (SOURCE_MANIFEST, APPROVED_MANIFEST_SHA256),
        (r"bin\direct-images.exe", APPROVED_IMAGE_TOOL_SHA256),
        (r"bin\openvmm.exe", APPROVED_OPENVMM_SHA256),
        (r"guest\vmlinux", APPROVED_KERNEL_SHA256),
        (r"guest\initramfs-edge.cpio.gz", APPROVED_INITRD_SHA256),
    ] {
        super::abi::verify_file_digest(&directory.join(path), expected)?;
    }
    AgentLibrary::load_verified(
        &directory.join(r"bin\aci_edge_agent.dll"),
        APPROVED_DLL_SHA256,
    )
}

fn discover_bundle_with(
    variable: impl Fn(&str) -> Option<OsString>,
    executable: impl FnOnce() -> io::Result<PathBuf>,
) -> Result<PathBuf, MxcError> {
    if let Some(directory) = variable(ARTIFACTS_DIR_ENV).filter(|value| !value.is_empty()) {
        let directory = PathBuf::from(directory);
        if directory.join(SOURCE_MANIFEST).is_file() {
            return Ok(directory);
        }
        return Err(MxcError::backend_unavailable(format!(
            "NVX signed bundled agent: {ARTIFACTS_DIR_ENV} names {}, which holds no agent bundle",
            directory.display()
        )));
    }
    let executable = executable().map_err(|error| {
        MxcError::backend_unavailable(format!(
            "NVX signed bundled agent: cannot locate the current executable; set {ARTIFACTS_DIR_ENV}: {error}"
        ))
    })?;
    let directory = executable.parent().ok_or_else(|| {
        MxcError::backend_unavailable(format!(
            "NVX signed bundled agent: {} is not in a directory; set {ARTIFACTS_DIR_ENV}",
            executable.display()
        ))
    })?;
    let found = [Some(directory), directory.parent()]
        .into_iter()
        .flatten()
        .map(|candidate| candidate.join(BESIDE_EXE_DIR))
        .find(|candidate| candidate.join(SOURCE_MANIFEST).is_file());
    found.ok_or_else(|| {
        MxcError::backend_unavailable(format!(
            "NVX signed bundled agent: no agent bundle is beside {}: copy the {BESIDE_EXE_DIR} \
             directory that the build staged next to the executable or its directory, or set \
             {ARTIFACTS_DIR_ENV}",
            directory.display()
        ))
    })
}

struct ExecGuard<'a> {
    library: &'a AgentLibrary,
    handle: Option<u64>,
    cancel_on_drop: bool,
}

impl<'a> ExecGuard<'a> {
    fn new(library: &'a AgentLibrary, handle: u64) -> Self {
        Self {
            library,
            handle: Some(handle),
            cancel_on_drop: true,
        }
    }

    fn cancel_and_release(&mut self) -> Result<(), MxcError> {
        let Some(handle) = self.handle.take() else {
            return Ok(());
        };
        self.cancel_on_drop = false;
        let cancel_error = self.library.exec_cancel(handle).err();
        let release_error = self.library.exec_release(handle).err();
        match (cancel_error, release_error) {
            (None, None) => Ok(()),
            (Some(mut cancel), Some(release)) => {
                cancel.message.push_str("; release failure: ");
                cancel.message.push_str(&release.to_string());
                Err(cancel)
            }
            (Some(error), None) | (None, Some(error)) => Err(error),
        }
    }

    fn release(&mut self) -> Result<(), MxcError> {
        let Some(handle) = self.handle.take() else {
            return Ok(());
        };
        self.cancel_on_drop = false;
        self.library.exec_release(handle)
    }
}

impl Drop for ExecGuard<'_> {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            if self.cancel_on_drop {
                let _ = self.library.exec_cancel(handle);
            }
            let _ = self.library.exec_release(handle);
        }
    }
}

fn remaining_timeout_ms(deadline: Option<Instant>) -> Option<u64> {
    let deadline = deadline?;
    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
        return Some(0);
    };
    let millis = u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX);
    if millis == 0 && !remaining.is_zero() {
        Some(1)
    } else {
        Some(millis)
    }
}

fn append_cleanup_error(primary: &mut MxcError, cleanup: MxcError) {
    primary.message.push_str("; cleanup failure: ");
    primary.message.push_str(&cleanup.to_string());
}

impl NvxClient {
    fn exec_and_wait_with_capture_limit(
        &self,
        sandbox_id: &SandboxId,
        request: &ExecRequest,
        capture_limit: usize,
    ) -> Result<ExecOutput, MxcError> {
        let exec_handle = self.library.exec(
            self.host,
            sandbox_id.token(),
            &ExecInput {
                request: request.clone(),
                stdin: false,
            },
        )?;
        let mut guard = ExecGuard::new(self.library, exec_handle);
        let deadline = request
            .process
            .timeout
            .filter(|&ms| ms != 0)
            .and_then(|ms| {
                Instant::now().checked_add(Duration::from_millis(
                    ms.saturating_add(HOST_TIMEOUT_SLACK_MS),
                ))
            });

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        loop {
            let step =
                self.library
                    .exec_next(
                        exec_handle,
                        remaining_timeout_ms(deadline),
                        |event| {
                            let captured = stdout.len() + stderr.len();
                            let (buffer, bytes) = match event {
                                Event::Stdout(bytes) => (&mut stdout, bytes),
                                Event::Stderr(bytes) => (&mut stderr, bytes),
                                Event::Exit(bytes) => {
                                    return serde_json::from_slice::<ExecEnd>(bytes)
                                        .map(Some)
                                        .map_err(|parse_error| MxcError::backend_error(format!(
                                            "NVX signed bundled agent: the agent library returned a malformed execution end: {parse_error}"
                                        )));
                                }
                            };
                            // Check the combined budget before either buffer can grow.
                            if bytes.len() > capture_limit - captured {
                                return Err(MxcError::backend_error(format!(
                                    "NVX signed bundled agent: combined stdout/stderr capture limit of {capture_limit} bytes exceeded"
                                )));
                            }
                            buffer.extend_from_slice(bytes);
                            Ok(None)
                        },
                    )
                    .and_then(|step| step.transpose());

            match step {
                Ok(Some(None)) => {}
                Ok(Some(Some(ExecEnd::Outcome(outcome)))) => {
                    guard.release()?;
                    return Ok(ExecOutput {
                        outcome,
                        stdout,
                        stderr,
                    });
                }
                Ok(Some(Some(ExecEnd::Error(body)))) => {
                    let mut error = map_error_body(body);
                    if let Err(release_error) = guard.release() {
                        append_cleanup_error(&mut error, release_error);
                    }
                    return Err(error);
                }
                Ok(None) => {
                    guard.cancel_and_release()?;
                    return Ok(ExecOutput {
                        outcome: ExecOutcome::TimedOut,
                        stdout,
                        stderr,
                    });
                }
                Err(mut error) => {
                    if let Err(cleanup_error) = guard.cancel_and_release() {
                        append_cleanup_error(&mut error, cleanup_error);
                    }
                    return Err(error);
                }
            }
        }
    }
}

impl SandboxClient for NvxClient {
    fn capabilities(&self) -> Result<Capabilities, MxcError> {
        self.library.capabilities(self.host)
    }

    fn validate_provision(&self, input: &ProvisionInput) -> Result<(), MxcError> {
        self.library.validate_provision(self.host, input)
    }

    fn validate_exec(&self, request: &ExecRequest) -> Result<(), MxcError> {
        self.library.validate_exec(self.host, request)
    }

    fn probe(&self) -> Result<(), MxcError> {
        self.library.probe(self.host)
    }

    fn provision(&self, input: &ProvisionInput) -> Result<SandboxId, MxcError> {
        let reply = self.library.provision(self.host, input)?;
        SandboxId::from_token(&reply.token)
    }

    fn start(&self, sandbox_id: &SandboxId) -> Result<(), MxcError> {
        self.library
            .start(self.host, sandbox_id.token())
            .map(|_| ())
    }

    fn exec(&self, sandbox_id: &SandboxId, request: &ExecRequest) -> Result<Execution, MxcError> {
        self.validate_exec(request)?;
        let handle = self.library.exec(
            self.host,
            sandbox_id.token(),
            &ExecInput {
                request: request.clone(),
                stdin: request.stdin,
            },
        )?;
        super::execution::launch(self.library, handle, request)
    }

    fn provision_metadata(
        &self,
        input: &ProvisionInput,
    ) -> Result<(SandboxId, Option<serde_json::Value>), MxcError> {
        self.validate_provision(input)?;
        let reply = self.library.provision(self.host, input)?;
        Ok((
            SandboxId::from_token(&reply.token)?,
            reply.metadata.map(serde_json::Value::Object),
        ))
    }

    fn exec_and_wait(
        &self,
        sandbox_id: &SandboxId,
        request: &ExecRequest,
    ) -> Result<ExecOutput, MxcError> {
        self.exec_and_wait_with_capture_limit(sandbox_id, request, CAPTURE_LIMIT_BYTES)
    }

    fn stop(&self, sandbox_id: &SandboxId) -> Result<(), MxcError> {
        self.library.stop(self.host, sandbox_id.token()).map(|_| ())
    }

    fn deprovision(&self, sandbox_id: &SandboxId) -> Result<(), MxcError> {
        self.library
            .deprovision(self.host, sandbox_id.token())
            .map(|_| ())
    }

    fn close(&mut self) -> Result<(), MxcError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.library.host_close(self.host)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::ptr;
    use std::sync::{Mutex, OnceLock, PoisonError};

    use crate::mxc_common::mxc_error::MxcErrorCode;

    use super::super::abi::{
        ErrorBody, ExecEvent, Exports, WireErrorCode, EVENT_EXIT, EVENT_STDERR, EVENT_STDOUT,
        STATUS_ERROR, STATUS_INVALID_ARGUMENT, STATUS_INVALID_HANDLE, STATUS_OK, STATUS_PANIC,
        STATUS_TIMEOUT,
    };
    use super::*;

    fn write_bundle_manifest(directory: &Path) -> PathBuf {
        fs::create_dir_all(directory).unwrap();
        fs::write(directory.join(SOURCE_MANIFEST), "{}").unwrap();
        directory.to_path_buf()
    }

    #[test]
    fn bundle_discovery_honors_env_override_without_fallback_and_checks_exe_neighbors() {
        let root = tempfile::tempdir().unwrap();
        let exe_dir = root.path().join("deps");
        fs::create_dir_all(&exe_dir).unwrap();

        let no_env = |_: &str| None;
        let exe_in = |dir: &Path| {
            let path = dir.join("test.exe");
            move || Ok(path)
        };

        let missing = discover_bundle_with(no_env, exe_in(&exe_dir)).unwrap_err();
        assert_eq!(missing.code, MxcErrorCode::BackendUnavailable);
        assert!(missing.message.contains(ARTIFACTS_DIR_ENV));

        let parent_bundle = write_bundle_manifest(&root.path().join(BESIDE_EXE_DIR));
        assert_eq!(
            discover_bundle_with(no_env, exe_in(&exe_dir)).unwrap(),
            parent_bundle
        );

        let beside_bundle = write_bundle_manifest(&exe_dir.join(BESIDE_EXE_DIR));
        assert_eq!(
            discover_bundle_with(no_env, exe_in(&exe_dir)).unwrap(),
            beside_bundle
        );

        let absent_override = root.path().join("absent");
        let bad_env = |name: &str| {
            (name == ARTIFACTS_DIR_ENV).then(|| absent_override.as_os_str().to_owned())
        };
        let err = discover_bundle_with(bad_env, exe_in(&exe_dir)).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::BackendUnavailable);
        assert!(err.message.contains("holds no agent bundle"));
    }

    #[test]
    fn review_discovery_requires_approved_runtime_without_opening_host() {
        let source = discover_bundle_dir().unwrap();
        load_bundle_library(&source).unwrap();
        let root = tempfile::tempdir().unwrap();
        let files = [
            "bundle-manifest.json",
            SOURCE_MANIFEST,
            r"bin\aci_edge_agent.dll",
            r"bin\direct-images.exe",
            r"bin\openvmm.exe",
            r"guest\vmlinux",
            r"guest\initramfs-edge.cpio.gz",
        ];
        for file in files {
            let path = root.path().join(file);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::copy(source.join(file), path).unwrap();
        }
        for file in files {
            let path = root.path().join(file);
            fs::remove_file(&path).unwrap();
            let error = load_bundle_library(root.path()).unwrap_err();
            assert_eq!(error.code, MxcErrorCode::BackendUnavailable);
            assert!(
                error.message.contains(
                    std::path::Path::new(file)
                        .file_name()
                        .unwrap()
                        .to_str()
                        .unwrap()
                ),
                "{file}: {error}"
            );
            if file != "bundle-manifest.json" {
                fs::write(&path, b"tampered runtime bytes").unwrap();
                let error = load_bundle_library(root.path()).unwrap_err();
                assert_eq!(error.code, MxcErrorCode::BackendUnavailable);
                assert!(
                    error.message.contains("approved SHA-256"),
                    "{file}: {error}"
                );
            }
            fs::copy(source.join(file), path).unwrap();
        }
        assert!(
            !root.path().join("aci").exists(),
            "read-only discovery opened native state"
        );
    }

    #[test]
    fn sandbox_id_requires_32_lowercase_hex_digits() {
        let valid = SandboxId::from_token("0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(
            valid.to_string(),
            "aci-edge-sandboxes:0123456789abcdef0123456789abcdef"
        );
        assert_eq!(valid.token(), "0123456789abcdef0123456789abcdef");

        for invalid in [
            "",
            "0123456789abcdef",
            "0123456789ABCDEF0123456789abcdef",
            "0123456789abcdef0123456789abcdeg",
        ] {
            let err = SandboxId::from_token(invalid).unwrap_err();
            assert_eq!(err.code, MxcErrorCode::BackendError);
        }
    }

    #[test]
    fn signed_library_validates_image_and_policy_without_provisioning() {
        let state_root = tempfile::tempdir().unwrap();
        let mut client = create_client(state_root.path()).unwrap();
        let result = (|| {
            let capabilities = client.capabilities()?;
            assert!(capabilities.spec.image_reference);
            assert!(capabilities.spec.memory);
            assert!(capabilities.exec.stdin);
            assert!(capabilities.exec.cancel);
            assert!(capabilities.filesystem.readonly_paths);
            assert!(capabilities.filesystem.readwrite_paths);
            assert!(capabilities.filesystem.denied_paths);
            assert!(capabilities.network.egress_rules);
            assert!(capabilities.network.network_proxy);
            let mut request = crate::mxc_common::models::ExecutionRequest {
                microvm_image: Some("python:3.12-alpine".to_owned()),
                microvm_memory_mib: Some(512),
                script_code: "printf ok".to_owned(),
                ..Default::default()
            };
            request.policy.network_specified = true;
            request.policy.network_egress = Some(Default::default());
            request.policy.network_ingress = Some(Default::default());
            let (provision, spec) =
                super::super::policy::provision_request(&request, None, &capabilities)?;
            let mut input = ProvisionInput {
                request: provision,
                spec,
            };
            client.validate_provision(&input)?;
            assert_eq!(
                serde_json::to_value(&input).unwrap()["spec"]["resources"]["memoryMib"],
                512
            );
            client.validate_exec(&super::super::policy::exec_request(
                &request,
                false,
                &capabilities,
            )?)?;
            input.request.runtime_config = Some(super::super::abi::RuntimeConfig {
                network_proxy: Some("http://192.0.2.1:3128".to_owned()),
            });
            let error = client.validate_provision(&input).unwrap_err();
            assert_eq!(error.code, MxcErrorCode::PolicyValidation);
            assert_eq!(
                error.message,
                "NVX signed bundled agent: \"http://192.0.2.1:3128\" must name host loopback: 127.0.0.1 or localhost"
            );
            Ok::<_, MxcError>(())
        })();
        let close = client.close();
        result.unwrap();
        close.unwrap();
    }

    #[test]
    #[ignore = "requires Windows x64, WHP and the signed agent bundle; does not provision a VM"]
    fn signed_agent_probe_verifies_host_without_provisioning() {
        let state = tempfile::tempdir().unwrap();
        let mut client = create_client(state.path()).unwrap();
        let probe = client.probe();
        let closed = client.close();
        probe.expect("signed NVX agent must confirm the host virtualization prerequisites");
        closed.unwrap();
        println!("HOST_VERIFIED signed NVX agent probe; no VM provisioned");
    }

    enum FakeStep {
        Event {
            kind: u32,
            bytes: Option<Vec<u8>>,
            reported_len: Option<usize>,
        },
        Status(i32),
    }

    struct FakeExecState {
        steps: VecDeque<FakeStep>,
        last_buf: Vec<u8>,
        calls: Vec<&'static str>,
        cancel_status: i32,
        release_status: i32,
        timeouts: Vec<i64>,
        validation_input: Option<serde_json::Value>,
        validation_error: Option<ErrorBody>,
        input: Vec<u8>,
        echo_input: bool,
        blocked_input: bool,
        input_closed: bool,
        write_status: i32,
        wait_for_input_failure: bool,
        next_entered: bool,
        write_failed: bool,
    }

    static FAKE_EXECS: OnceLock<Mutex<std::collections::BTreeMap<u64, FakeExecState>>> =
        OnceLock::new();
    static NEXT_HANDLE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(100);

    fn register_fake_exec(steps: Vec<FakeStep>) -> u64 {
        let handle = NEXT_HANDLE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        FAKE_EXECS
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                handle,
                FakeExecState {
                    steps: steps.into(),
                    last_buf: Vec::new(),
                    calls: Vec::new(),
                    cancel_status: STATUS_OK,
                    release_status: STATUS_OK,
                    timeouts: Vec::new(),
                    validation_input: None,
                    validation_error: None,
                    input: Vec::new(),
                    echo_input: false,
                    blocked_input: false,
                    input_closed: false,
                    write_status: STATUS_OK,
                    wait_for_input_failure: false,
                    next_entered: false,
                    write_failed: false,
                },
            );
        handle
    }

    fn outcome_step(outcome: ExecOutcome) -> FakeStep {
        FakeStep::Event {
            kind: EVENT_EXIT,
            bytes: Some(serde_json::to_vec(&ExecEnd::Outcome(outcome)).unwrap()),
            reported_len: None,
        }
    }

    fn test_id() -> SandboxId {
        SandboxId::from_token("0123456789abcdef0123456789abcdef").unwrap()
    }

    #[test]
    fn native_streaming_roundtrips_binary_stdin_and_releases_after_eof() {
        use std::io::{Read, Write};
        let handle = register_fake_exec(Vec::new());
        FAKE_EXECS
            .get()
            .unwrap()
            .lock()
            .unwrap()
            .get_mut(&handle)
            .unwrap()
            .echo_input = true;
        let client = NvxClient::from_library(fake_library(), handle);
        let mut request = ExecRequest::command_line("cat");
        request.stdin = true;
        let mut execution = client.exec(&test_id(), &request).unwrap();
        let mut input = execution.take_stdin().unwrap();
        let mut output = execution.take_stdout().unwrap();
        let mut errors = execution.take_stderr().unwrap();
        let output = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            output.read_to_end(&mut bytes).unwrap();
            bytes
        });
        let errors = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            errors.read_to_end(&mut bytes).unwrap();
            bytes
        });
        let payload = (0..2 * 1024 * 1024)
            .map(|n| (n % 256) as u8)
            .collect::<Vec<_>>();
        input.write_all(&payload).unwrap();
        drop(input);
        assert_eq!(execution.wait().unwrap(), ExecOutcome::Exited(7));
        assert_eq!(output.join().unwrap(), payload);
        assert_eq!(errors.join().unwrap(), [0xff, 0x00, 0xfe]);
        assert_eq!(fake_calls(handle), ["validate", "close_input", "release"]);
    }

    #[test]
    fn native_streaming_deadline_interrupts_backpressured_output_and_releases_once() {
        let handle = register_fake_exec(vec![
            FakeStep::Event {
                kind: EVENT_STDOUT,
                bytes: Some(vec![b'x'; 1024 * 1024]),
                reported_len: None,
            },
            outcome_step(ExecOutcome::Exited(0)),
        ]);
        let client = NvxClient::from_library(fake_library(), handle);
        let execution = client
            .exec(
                &test_id(),
                &ExecRequest::command_line("output").with_timeout_ms(25),
            )
            .unwrap();
        let started = Instant::now();
        assert_eq!(execution.wait().unwrap(), ExecOutcome::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(fake_calls(handle), ["validate", "cancel", "release"]);
    }

    #[test]
    fn native_streaming_cancel_unblocks_input_credit_before_release() {
        use std::io::Write;
        let handle = register_fake_exec(Vec::new());
        FAKE_EXECS
            .get()
            .unwrap()
            .lock()
            .unwrap()
            .get_mut(&handle)
            .unwrap()
            .blocked_input = true;
        let client = NvxClient::from_library(fake_library(), handle);
        let mut request = ExecRequest::command_line("sleep");
        request.stdin = true;
        let mut execution = client.exec(&test_id(), &request).unwrap();
        let mut input = execution.take_stdin().unwrap();
        input.write_all(b"input waiting for native credit").unwrap();
        execution.canceller().cancel().unwrap();
        assert_eq!(execution.wait().unwrap(), ExecOutcome::Cancelled);
        assert_eq!(fake_calls(handle), ["validate", "cancel", "release"]);
    }

    #[test]
    fn native_streaming_protocol_failure_cancels_and_preserves_release_failure() {
        let handle = register_fake_exec(vec![FakeStep::Status(STATUS_INVALID_ARGUMENT)]);
        FAKE_EXECS
            .get()
            .unwrap()
            .lock()
            .unwrap()
            .get_mut(&handle)
            .unwrap()
            .release_status = STATUS_INVALID_HANDLE;
        let client = NvxClient::from_library(fake_library(), handle);
        let execution = client
            .exec(&test_id(), &ExecRequest::command_line("invalid"))
            .unwrap();
        let error = execution.wait().unwrap_err();
        assert!(error.message.contains("rejected an argument"), "{error}");
        assert!(error.message.contains("cleanup failure"), "{error}");
        assert_eq!(fake_calls(handle), ["validate", "cancel", "release"]);
    }

    #[test]
    fn review_cancel_refusal_interrupts_blocked_output_and_completes() {
        use std::io::Read;
        for kind in [EVENT_STDOUT, EVENT_STDERR] {
            let handle = register_fake_exec(vec![FakeStep::Event {
                kind,
                bytes: Some(vec![b'x'; 1024 * 1024]),
                reported_len: None,
            }]);
            FAKE_EXECS
                .get()
                .unwrap()
                .lock()
                .unwrap()
                .get_mut(&handle)
                .unwrap()
                .cancel_status = STATUS_PANIC;
            let client = NvxClient::from_library(fake_library(), handle);
            let mut execution = client
                .exec(
                    &test_id(),
                    &ExecRequest::command_line("output").with_timeout_ms(25),
                )
                .unwrap();
            let mut output = if kind == EVENT_STDOUT {
                execution.take_stdout().unwrap()
            } else {
                execution.take_stderr().unwrap()
            };
            let canceller = execution.canceller();
            let (tx, rx) = std::sync::mpsc::channel();
            let waiter = std::thread::spawn(move || tx.send(execution.wait()).unwrap());
            let completed = rx.recv_timeout(Duration::from_secs(2));
            let was_finite = completed.is_ok();
            // Rescue the old blocked-writer path before asserting so the regression leaves no worker.
            if !was_finite {
                FAKE_EXECS
                    .get()
                    .unwrap()
                    .lock()
                    .unwrap()
                    .get_mut(&handle)
                    .unwrap()
                    .steps
                    .push_back(outcome_step(ExecOutcome::Exited(0)));
            }
            let mut bytes = Vec::new();
            output.read_to_end(&mut bytes).unwrap();
            let result =
                completed.unwrap_or_else(|_| rx.recv_timeout(Duration::from_secs(2)).unwrap());
            waiter.join().unwrap();
            assert!(
                was_finite,
                "rejected cancellation left output or owned teardown blocked"
            );
            let error = result.unwrap_err();
            assert_eq!(error.code, MxcErrorCode::BackendError);
            assert!(error.message.contains("agent library panicked"), "{error}");
            let calls = fake_calls(handle);
            assert_eq!(
                canceller.cancel().unwrap_err(),
                error,
                "release must not turn a refused cancellation into success"
            );
            assert_eq!(
                fake_calls(handle),
                calls,
                "a retained canceller used a released native handle"
            );
            assert_eq!(fake_calls(handle), ["validate", "cancel", "release"]);
        }
    }

    #[test]
    fn review_protocol_error_preserves_refused_cancellation() {
        let handle = register_fake_exec(vec![FakeStep::Status(STATUS_INVALID_ARGUMENT)]);
        FAKE_EXECS
            .get()
            .unwrap()
            .lock()
            .unwrap()
            .get_mut(&handle)
            .unwrap()
            .cancel_status = STATUS_PANIC;
        let client = NvxClient::from_library(fake_library(), handle);
        let error = client
            .exec(&test_id(), &ExecRequest::command_line("invalid"))
            .unwrap()
            .wait()
            .unwrap_err();
        assert_eq!(error.code, MxcErrorCode::BackendError);
        assert!(error.message.contains("rejected an argument"), "{error}");
        assert!(error.message.contains("cleanup failure"), "{error}");
        assert!(error.message.contains("agent library panicked"), "{error}");
        assert_eq!(fake_calls(handle), ["validate", "cancel", "release"]);
    }

    #[test]
    fn review_protocol_stdin_and_cancel_errors_are_combined() {
        use std::io::Write;
        let handle = register_fake_exec(vec![FakeStep::Status(STATUS_INVALID_ARGUMENT)]);
        {
            let mut map = FAKE_EXECS.get().unwrap().lock().unwrap();
            let state = map.get_mut(&handle).unwrap();
            state.cancel_status = STATUS_PANIC;
            state.write_status = STATUS_ERROR;
            state.wait_for_input_failure = true;
        }
        let client = NvxClient::from_library(fake_library(), handle);
        let mut request = ExecRequest::command_line("input");
        request.stdin = true;
        let mut execution = client.exec(&test_id(), &request).unwrap();
        let mut stdin = execution.take_stdin().unwrap();
        stdin.write_all(b"rejected input").unwrap();
        let error = execution.wait().unwrap_err();
        assert_eq!(error.code, MxcErrorCode::BackendError);
        assert!(error.message.contains("rejected an argument"), "{error}");
        assert!(error.message.contains("injected stdin failure"), "{error}");
        assert!(error.message.contains("agent library panicked"), "{error}");
        assert_eq!(fake_calls(handle), ["validate", "cancel", "release"]);
    }

    #[test]
    fn review_stdin_failure_and_refused_cancel_complete_without_an_exit_event() {
        use std::io::Write;
        let handle = register_fake_exec(Vec::new());
        {
            let mut map = FAKE_EXECS.get().unwrap().lock().unwrap();
            let state = map.get_mut(&handle).unwrap();
            state.write_status = STATUS_ERROR;
            state.cancel_status = STATUS_PANIC;
        }
        let client = NvxClient::from_library(fake_library(), handle);
        let mut request = ExecRequest::command_line("input");
        request.stdin = true;
        let mut execution = client.exec(&test_id(), &request).unwrap();
        execution
            .take_stdin()
            .unwrap()
            .write_all(b"failed input")
            .unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || tx.send(execution.wait()).unwrap());
        let result = rx.recv_timeout(Duration::from_secs(2));
        let finite = result.is_ok();
        if !finite {
            FAKE_EXECS
                .get()
                .unwrap()
                .lock()
                .unwrap()
                .get_mut(&handle)
                .unwrap()
                .steps
                .push_back(outcome_step(ExecOutcome::Exited(0)));
        }
        let result = result.unwrap_or_else(|_| rx.recv_timeout(Duration::from_secs(2)).unwrap());
        waiter.join().unwrap();
        assert!(
            finite,
            "stdin failure depended on an unconfirmed native exit"
        );
        let error = result.unwrap_err();
        assert_eq!(error.code, MxcErrorCode::BackendError);
        assert!(error.message.contains("injected stdin failure"), "{error}");
        assert!(error.message.contains("agent library panicked"), "{error}");
        assert_eq!(fake_calls(handle), ["validate", "cancel", "release"]);
    }

    fn fake_calls(handle: u64) -> Vec<&'static str> {
        FAKE_EXECS
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&handle)
            .map(|s| s.calls.clone())
            .unwrap_or_default()
    }

    fn alloc_buf(bytes: &[u8], out: *mut *mut u8, len: *mut usize) {
        let mut owned = bytes.to_vec().into_boxed_slice();
        unsafe {
            *len = owned.len();
            *out = owned.as_mut_ptr();
        }
        std::mem::forget(owned);
    }

    unsafe extern "C" fn fake_buffer_free(ptr: *mut u8, len: usize) {
        if !ptr.is_null() {
            unsafe {
                drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)));
            }
        }
    }

    unsafe extern "C" fn fake_host_open(
        _in_ptr: *const u8,
        _in_len: usize,
        host: *mut u64,
        _out: *mut *mut u8,
        _len: *mut usize,
    ) -> i32 {
        unsafe { *host = 1 };
        STATUS_OK
    }

    unsafe extern "C" fn fake_release(handle: u64) -> i32 {
        if let Some(state) = FAKE_EXECS
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(&handle)
        {
            state.calls.push("release");
            return state.release_status;
        }
        if handle == 999 {
            STATUS_INVALID_HANDLE
        } else {
            STATUS_OK
        }
    }

    unsafe extern "C" fn fake_probe(host: u64, out: *mut *mut u8, len: *mut usize) -> i32 {
        if host == 2 {
            alloc_buf(b"{}", out, len);
            STATUS_OK
        } else if host == 3 {
            let body = serde_json::to_vec(&ErrorBody {
                code: WireErrorCode::BackendUnavailable,
                message: "WHP disabled".to_owned(),
            })
            .unwrap();
            alloc_buf(&body, out, len);
            STATUS_ERROR
        } else {
            STATUS_OK
        }
    }

    unsafe extern "C" fn fake_query_cancel(
        handle: u64,
        _out: *mut *mut u8,
        _len: *mut usize,
    ) -> i32 {
        if let Some(state) = FAKE_EXECS
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(&handle)
        {
            state.calls.push("cancel");
            if state.cancel_status == STATUS_OK && state.steps.is_empty() {
                state.steps.push_back(outcome_step(ExecOutcome::Cancelled));
            }
            return state.cancel_status;
        }
        STATUS_OK
    }

    unsafe extern "C" fn fake_query_invalid(
        _handle: u64,
        _out: *mut *mut u8,
        _len: *mut usize,
    ) -> i32 {
        STATUS_INVALID_HANDLE
    }

    unsafe extern "C" fn fake_call_invalid(
        _host: u64,
        _in_ptr: *const u8,
        _in_len: usize,
        _out: *mut *mut u8,
        _len: *mut usize,
    ) -> i32 {
        STATUS_INVALID_HANDLE
    }

    unsafe extern "C" fn fake_validate_exec(
        host: u64,
        input: *const u8,
        input_len: usize,
        out: *mut *mut u8,
        len: *mut usize,
    ) -> i32 {
        let mut map = FAKE_EXECS
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let Some(state) = map.get_mut(&host) else {
            return STATUS_INVALID_HANDLE;
        };
        state.calls.push("validate");
        let input = unsafe { std::slice::from_raw_parts(input, input_len) };
        let Ok(value) = serde_json::from_slice(input) else {
            return STATUS_INVALID_ARGUMENT;
        };
        state.validation_input = Some(value);
        if let Some(error) = &state.validation_error {
            alloc_buf(&serde_json::to_vec(error).unwrap(), out, len);
            STATUS_ERROR
        } else {
            STATUS_OK
        }
    }

    unsafe extern "C" fn fake_exec(
        host: u64,
        _tok_ptr: *const u8,
        _tok_len: usize,
        _in_ptr: *const u8,
        _in_len: usize,
        exec_out: *mut u64,
        _out: *mut *mut u8,
        _len: *mut usize,
    ) -> i32 {
        unsafe { *exec_out = host };
        STATUS_OK
    }

    unsafe extern "C" fn fake_exec_next(handle: u64, timeout: i64, event: *mut ExecEvent) -> i32 {
        let mut map = FAKE_EXECS
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        loop {
            let Some(state) = map.get_mut(&handle) else {
                return STATUS_INVALID_HANDLE;
            };
            state.next_entered = true;
            if !state.wait_for_input_failure || state.write_failed {
                break;
            }
            drop(map);
            std::thread::yield_now();
            map = FAKE_EXECS.get().unwrap().lock().unwrap();
        }
        let Some(state) = map.get_mut(&handle) else {
            return STATUS_INVALID_HANDLE;
        };
        state.timeouts.push(timeout);
        match state.steps.pop_front() {
            Some(FakeStep::Event {
                kind,
                bytes: Some(bytes),
                reported_len,
            }) => {
                state.last_buf = bytes;
                let length = reported_len.unwrap_or(state.last_buf.len());
                unsafe {
                    *event = ExecEvent {
                        kind,
                        data: state.last_buf.as_ptr(),
                        length,
                    };
                }
                STATUS_OK
            }
            Some(FakeStep::Event {
                kind,
                bytes: None,
                reported_len,
            }) => {
                unsafe {
                    *event = ExecEvent {
                        kind,
                        data: ptr::null(),
                        length: reported_len.unwrap_or(4),
                    };
                }
                STATUS_OK
            }
            Some(FakeStep::Status(status)) => status,
            None => STATUS_TIMEOUT,
        }
    }

    unsafe extern "C" fn fake_exec_write(
        handle: u64,
        input: *const u8,
        len: usize,
        _timeout: i64,
        written: *mut usize,
        out: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32 {
        let mut map = FAKE_EXECS.get().unwrap().lock().unwrap();
        loop {
            let Some(state) = map.get_mut(&handle) else {
                return STATUS_INVALID_HANDLE;
            };
            if !state.wait_for_input_failure || state.next_entered {
                break;
            }
            drop(map);
            std::thread::yield_now();
            map = FAKE_EXECS.get().unwrap().lock().unwrap();
        }
        let Some(state) = map.get_mut(&handle) else {
            return STATUS_INVALID_HANDLE;
        };
        if state.blocked_input {
            return STATUS_TIMEOUT;
        }
        if state.write_status != STATUS_OK {
            state.write_failed = true;
            if state.write_status == STATUS_ERROR {
                alloc_buf(
                    &serde_json::to_vec(&ErrorBody {
                        code: WireErrorCode::BackendError,
                        message: "injected stdin failure".to_owned(),
                    })
                    .unwrap(),
                    out,
                    out_len,
                );
            }
            return state.write_status;
        }
        let accepted = len.min(32 * 1024);
        state
            .input
            .extend_from_slice(unsafe { std::slice::from_raw_parts(input, accepted) });
        unsafe { *written = accepted };
        STATUS_OK
    }

    unsafe extern "C" fn fake_close_input(handle: u64, _: *mut *mut u8, _: *mut usize) -> i32 {
        let mut map = FAKE_EXECS.get().unwrap().lock().unwrap();
        let Some(state) = map.get_mut(&handle) else {
            return STATUS_INVALID_HANDLE;
        };
        state.calls.push("close_input");
        if state.input_closed {
            return STATUS_INVALID_ARGUMENT;
        }
        state.input_closed = true;
        if state.echo_input {
            state.steps.push_back(FakeStep::Event {
                kind: EVENT_STDOUT,
                bytes: Some(state.input.clone()),
                reported_len: None,
            });
            state.steps.push_back(FakeStep::Event {
                kind: EVENT_STDERR,
                bytes: Some(vec![0xff, 0x00, 0xfe]),
                reported_len: None,
            });
            state.steps.push_back(outcome_step(ExecOutcome::Exited(7)));
        }
        STATUS_OK
    }

    fn fake_library() -> &'static AgentLibrary {
        static LIB: OnceLock<AgentLibrary> = OnceLock::new();
        LIB.get_or_init(|| {
            AgentLibrary::from_exports_for_test(Exports {
                host_open: fake_host_open,
                host_close: fake_release,
                host_info: fake_query_invalid,
                capabilities: fake_query_invalid,
                probe: fake_probe,
                validate_provision: fake_call_invalid,
                validate_exec: fake_validate_exec,
                provision: fake_call_invalid,
                start: fake_call_invalid,
                stop: fake_call_invalid,
                deprovision: fake_call_invalid,
                diagnostics: fake_call_invalid,
                guest_logs: fake_call_invalid,
                exec: fake_exec,
                exec_next: fake_exec_next,
                exec_write: fake_exec_write,
                exec_close_input: fake_close_input,
                exec_cancel: fake_query_cancel,
                exec_release: fake_release,
                image_register: fake_call_invalid,
                image_list: fake_query_invalid,
                image_verify: fake_call_invalid,
                image_unregister: fake_call_invalid,
                buffer_free: fake_buffer_free,
            })
        })
    }

    #[test]
    fn probe_and_host_close_fail_closed_on_unexpected_payload_or_status() {
        let lib = fake_library();
        assert!(lib.probe(1).is_ok());

        let unexpected_payload = lib.probe(2).unwrap_err();
        assert_eq!(unexpected_payload.code, MxcErrorCode::BackendError);
        assert!(unexpected_payload
            .message
            .contains("unexpected probe payload"));

        let unavailable = lib.probe(3).unwrap_err();
        assert_eq!(unavailable.code, MxcErrorCode::BackendUnavailable);
        assert!(unavailable.message.contains("WHP disabled"));

        assert!(lib.host_close(1).is_ok());
        let close_err = lib.host_close(999).unwrap_err();
        assert_eq!(close_err.code, MxcErrorCode::BackendError);
        assert!(close_err.message.contains("unknown handle"));
    }

    #[test]
    fn exec_and_wait_streams_bytes_and_handles_timeouts_and_protocol_errors() {
        let sandbox_id = SandboxId::from_token("0123456789abcdef0123456789abcdef").unwrap();
        let req = ExecRequest::command_line("echo test").with_timeout_ms(100);

        // 1. Normal stdout + stderr (with null bytes) + exit 42 -> release only.
        let handle = register_fake_exec(vec![
            FakeStep::Event {
                kind: EVENT_STDOUT,
                bytes: Some(b"out\0\xff".to_vec()),
                reported_len: None,
            },
            FakeStep::Event {
                kind: EVENT_STDERR,
                bytes: Some(b"err\0\x80".to_vec()),
                reported_len: None,
            },
            FakeStep::Event {
                kind: EVENT_EXIT,
                bytes: Some(br#"{"outcome":{"exited":42}}"#.to_vec()),
                reported_len: None,
            },
        ]);
        let mut client = NvxClient::from_library(fake_library(), handle);
        let output = client.exec_and_wait(&sandbox_id, &req).unwrap();
        assert_eq!(output.outcome, ExecOutcome::Exited(42));
        assert_eq!(output.stdout, b"out\0\xff");
        assert_eq!(output.stderr, b"err\0\x80");
        assert_eq!(fake_calls(handle), ["release"]);
        let _ = client.close();

        // 2. Host backstop STATUS_TIMEOUT -> cancels, releases, and preserves partial output.
        let handle = register_fake_exec(vec![
            FakeStep::Event {
                kind: EVENT_STDOUT,
                bytes: Some(b"partial-out".to_vec()),
                reported_len: None,
            },
            FakeStep::Status(STATUS_TIMEOUT),
        ]);
        let mut client = NvxClient::from_library(fake_library(), handle);
        let output = client.exec_and_wait(&sandbox_id, &req).unwrap();
        assert_eq!(output.outcome, ExecOutcome::TimedOut);
        assert_eq!(output.stdout, b"partial-out");
        assert_eq!(fake_calls(handle), ["cancel", "release"]);
        let _ = client.close();

        // 3. Unknown event kind -> cancels, releases, and fails closed.
        let handle = register_fake_exec(vec![FakeStep::Event {
            kind: 99,
            bytes: Some(b"unknown".to_vec()),
            reported_len: None,
        }]);
        let mut client = NvxClient::from_library(fake_library(), handle);
        let err = client.exec_and_wait(&sandbox_id, &req).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::BackendError);
        assert!(err.message.contains("unknown execution event 99"));
        assert_eq!(fake_calls(handle), ["cancel", "release"]);
        let _ = client.close();

        // 4. Missing event data (null pointer with non-zero length) -> cancels, releases, fails closed.
        let handle = register_fake_exec(vec![FakeStep::Event {
            kind: EVENT_STDOUT,
            bytes: None,
            reported_len: Some(8),
        }]);
        let mut client = NvxClient::from_library(fake_library(), handle);
        let err = client.exec_and_wait(&sandbox_id, &req).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::BackendError);
        assert!(err.message.contains("data is missing"));
        assert_eq!(fake_calls(handle), ["cancel", "release"]);
        let _ = client.close();

        // 5. Native STATUS_INVALID_ARGUMENT -> cancels, releases, fails closed.
        let handle = register_fake_exec(vec![FakeStep::Status(STATUS_INVALID_ARGUMENT)]);
        let mut client = NvxClient::from_library(fake_library(), handle);
        let err = client.exec_and_wait(&sandbox_id, &req).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::BackendError);
        assert!(err.message.contains("rejected an argument"));
        assert_eq!(fake_calls(handle), ["cancel", "release"]);
        let _ = client.close();
    }

    #[test]
    fn native_validation_sends_the_direct_request_and_preserves_native_error_codes() {
        let request = ExecRequest::command_line("printf '%s' \"$KEY\"")
            .with_timeout_ms(250)
            .with_cwd("/tmp".to_owned())
            .with_envs(vec!["KEY=first".to_owned(), "KEY=last".to_owned()])
            .with_inherit_default_env(true);
        for failure in [
            None,
            Some((
                WireErrorCode::PolicyValidation,
                MxcErrorCode::PolicyValidation,
            )),
            Some((
                WireErrorCode::MalformedRequest,
                MxcErrorCode::MalformedRequest,
            )),
            Some((
                WireErrorCode::BackendUnavailable,
                MxcErrorCode::BackendUnavailable,
            )),
        ] {
            let handle = register_fake_exec(Vec::new());
            if let Some((code, _)) = failure {
                FAKE_EXECS
                    .get()
                    .unwrap()
                    .lock()
                    .unwrap()
                    .get_mut(&handle)
                    .unwrap()
                    .validation_error = Some(ErrorBody {
                    code,
                    message: "native validation rejected request".to_owned(),
                });
            }
            let mut client = NvxClient::from_library(fake_library(), handle);
            let result = client.validate_exec(&request);
            if let Some((_, code)) = failure {
                let error = result.unwrap_err();
                assert_eq!(error.code, code);
                assert_eq!(
                    error.message,
                    "NVX signed bundled agent: native validation rejected request"
                );
            } else {
                result.unwrap();
            }
            assert_eq!(fake_calls(handle), ["validate"]);
            let input = FAKE_EXECS
                .get()
                .unwrap()
                .lock()
                .unwrap()
                .get(&handle)
                .unwrap()
                .validation_input
                .clone()
                .unwrap();
            assert_eq!(
                input,
                serde_json::json!({
                    "process": {
                        "commandLine": "printf '%s' \"$KEY\"",
                        "timeout": 250,
                        "cwd": "/tmp",
                        "env": ["KEY=first", "KEY=last"],
                        "inheritDefaultEnv": true
                    }
                })
            );
            client.close().unwrap();
        }
    }

    #[test]
    fn real_staged_native_validation_checks_process_limits_without_provisioning() {
        let state_root = tempfile::tempdir().unwrap();
        let mut client = create_client(state_root.path()).unwrap();
        let command = ExecRequest::command_line("printf forbidden");
        client.validate_exec(&command).unwrap();
        let boundary = command
            .clone()
            .with_cwd(format!("/{}", "\u{00e9}".repeat(2047)))
            .with_envs(vec!["KEY=value".to_owned(); 256])
            .with_inherit_default_env(true);
        client.validate_exec(&boundary).unwrap();
        for invalid in [
            boundary
                .clone()
                .with_cwd(format!("/{}x", "\u{00e9}".repeat(2047))),
            boundary.with_envs(vec!["KEY=value".to_owned(); 257]),
        ] {
            let error = client.validate_exec(&invalid).unwrap_err();
            assert_eq!(error.code, MxcErrorCode::PolicyValidation);
        }
        client.close().unwrap();
        state_root.close().unwrap();
    }

    #[test]
    fn capture_limit_preserves_bytes_at_and_below_the_combined_boundary() {
        let sandbox_id = SandboxId::from_token("0123456789abcdef0123456789abcdef").unwrap();
        let request = ExecRequest::command_line("test").with_timeout_ms(0);
        assert_eq!(CAPTURE_LIMIT_BYTES, 67_108_864);

        for stderr in [b"\x80\0\x81".as_slice(), b"\x80\0\x81x".as_slice()] {
            let handle = register_fake_exec(vec![
                FakeStep::Event {
                    kind: EVENT_STDOUT,
                    bytes: Some(b"\xff\0\xfex".to_vec()),
                    reported_len: None,
                },
                FakeStep::Event {
                    kind: EVENT_STDERR,
                    bytes: Some(stderr.to_vec()),
                    reported_len: None,
                },
                FakeStep::Event {
                    kind: EVENT_STDOUT,
                    bytes: Some(Vec::new()),
                    reported_len: None,
                },
                FakeStep::Event {
                    kind: EVENT_EXIT,
                    bytes: Some(br#"{"outcome":{"exited":42}}"#.to_vec()),
                    reported_len: None,
                },
            ]);
            let mut client = NvxClient::from_library(fake_library(), handle);
            let output = client
                .exec_and_wait_with_capture_limit(&sandbox_id, &request, 8)
                .unwrap();
            assert_eq!(output.outcome, ExecOutcome::Exited(42));
            assert_eq!(output.stdout, b"\xff\0\xfex");
            assert_eq!(output.stderr, stderr);
            assert_eq!(fake_calls(handle), ["release"]);
            client.close().unwrap();
        }
    }

    #[test]
    fn capture_overflow_cancels_releases_and_preserves_cleanup_failures_without_a_timeout() {
        let sandbox_id = SandboxId::from_token("0123456789abcdef0123456789abcdef").unwrap();
        let request = ExecRequest::command_line("test").with_timeout_ms(0);
        for (first_kind, second_kind, first_bytes, second_bytes) in [
            (EVENT_STDOUT, EVENT_STDERR, 4, 5),
            (EVENT_STDERR, EVENT_STDOUT, 4, 5),
            (EVENT_STDOUT, EVENT_STDOUT, 8, 1),
            (EVENT_STDERR, EVENT_STDERR, 0, 9),
        ] {
            for cleanup_fails in [false, true] {
                let handle = register_fake_exec(vec![
                    FakeStep::Event {
                        kind: first_kind,
                        bytes: Some(vec![b'a'; first_bytes]),
                        reported_len: None,
                    },
                    FakeStep::Event {
                        kind: second_kind,
                        bytes: Some(vec![b'b'; second_bytes]),
                        reported_len: None,
                    },
                    FakeStep::Event {
                        kind: EVENT_EXIT,
                        bytes: Some(br#"{"outcome":{"exited":0}}"#.to_vec()),
                        reported_len: None,
                    },
                ]);
                if cleanup_fails {
                    let mut map = FAKE_EXECS.get().unwrap().lock().unwrap();
                    let state = map.get_mut(&handle).unwrap();
                    state.cancel_status = STATUS_INVALID_ARGUMENT;
                    state.release_status = STATUS_INVALID_HANDLE;
                }
                let mut client = NvxClient::from_library(fake_library(), handle);
                let error = client
                    .exec_and_wait_with_capture_limit(&sandbox_id, &request, 8)
                    .unwrap_err();
                assert_eq!(error.code, MxcErrorCode::BackendError);
                let primary = "NVX signed bundled agent: combined stdout/stderr capture limit of 8 bytes exceeded";
                if cleanup_fails {
                    assert!(error.message.starts_with(primary));
                    assert!(error.message.contains("; cleanup failure: "));
                    assert!(error.message.contains("rejected an argument"));
                    assert!(error.message.contains("; release failure: "));
                    assert!(error.message.contains("unknown handle"));
                } else {
                    assert_eq!(error.message, primary);
                }
                assert_eq!(fake_calls(handle), ["cancel", "release"]);
                {
                    let map = FAKE_EXECS.get().unwrap().lock().unwrap();
                    let state = map.get(&handle).unwrap();
                    assert_eq!(
                        state.steps.len(),
                        1,
                        "must not consume the exit after overflow"
                    );
                    assert_eq!(state.timeouts, [-1, -1]);
                }
                // The fake host uses the same handle, so inspect execution cleanup before close.
                client.close().unwrap_or_else(|error| {
                    assert!(cleanup_fails, "unexpected close error: {error}");
                });
            }
        }
    }

    #[test]
    fn real_staged_dll_loads_verifies_cached_digest_and_rejects_bad_manifest() {
        let bundle_dir = discover_bundle_dir().expect("discover staged NVX bundle");
        let dll_path = bundle_dir.join("bin").join("aci_edge_agent.dll");
        let lib = AgentLibrary::load_verified(&dll_path, APPROVED_DLL_SHA256)
            .expect("load verified aci_edge_agent.dll");
        let lib_again = AgentLibrary::load_verified(&dll_path, APPROVED_DLL_SHA256)
            .expect("reuse cached verified aci_edge_agent.dll");
        assert!(std::ptr::eq(lib, lib_again));

        // Even after caching, a wrong expected digest for the same canonical path must fail closed.
        let wrong_dll_digest = AgentLibrary::load_verified(&dll_path, &"0".repeat(64)).unwrap_err();
        assert_eq!(wrong_dll_digest.code, MxcErrorCode::BackendUnavailable);

        // Passing a wrong manifest digest to host_open must be rejected by the native DLL.
        let state_root = tempfile::tempdir().unwrap();
        let bad_setup = SetupConfig {
            schema_version: 1,
            state_root: state_root.path().to_path_buf(),
            runtime: RuntimeSource {
                bundle: BundleSource {
                    path: bundle_dir,
                    manifest_sha256: "0".repeat(64),
                },
            },
        };
        let bad_host = lib.host_open(&bad_setup).unwrap_err();
        assert_eq!(bad_host.code, MxcErrorCode::BackendUnavailable);
    }
}

#[cfg(test)]
mod persistent_state_tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    #[test]
    fn persistent_state_admission_creates_private_root() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("nvx");

        admit_persistent_state_root(&root).unwrap();

        assert!(crate::mxc_common::filesystem_dacl::validate_owner_only_directory(&root).unwrap());
    }

    #[test]
    fn persistent_state_admission_rejects_permissive_existing_root_without_repair() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("nvx");
        std::fs::create_dir(&root).unwrap();
        assert!(
            !crate::mxc_common::filesystem_dacl::validate_owner_only_directory(&root).unwrap(),
            "test root unexpectedly inherited the exact private MXC DACL"
        );

        let error = admit_persistent_state_root(&root).unwrap_err();

        assert!(error.message.contains("owner or ACL is not private"));
        assert!(
            !crate::mxc_common::filesystem_dacl::validate_owner_only_directory(&root).unwrap(),
            "admission must not repair an existing permissive root"
        );
    }

    #[test]
    fn persistent_state_admission_rejects_junction() {
        let parent = tempfile::tempdir().unwrap();
        let target = parent.path().join("target");
        let root = parent.path().join("nvx");
        std::fs::create_dir(&target).unwrap();
        let status = std::process::Command::new("cmd")
            .args([
                "/c",
                "mklink",
                "/J",
                root.to_str().unwrap(),
                target.to_str().unwrap(),
            ])
            .status()
            .unwrap();
        assert!(
            status.success(),
            "mklink /J failed ({status}); junction creation needs no elevation"
        );

        let error = admit_persistent_state_root(&root).unwrap_err();

        assert!(error.message.contains("without a reparse point"));
        std::fs::remove_dir(&root).unwrap();
    }

    #[test]
    fn persistent_state_admission_is_race_safe_for_concurrent_initialization() {
        let parent = tempfile::tempdir().unwrap();
        let root = Arc::new(parent.path().join("nvx"));
        let workers = 8usize;
        let barrier = Arc::new(Barrier::new(workers));
        let mut joins = Vec::with_capacity(workers);

        for _ in 0..workers {
            let root = Arc::clone(&root);
            let barrier = Arc::clone(&barrier);
            joins.push(std::thread::spawn(move || {
                barrier.wait();
                admit_persistent_state_root(root.as_path())
            }));
        }

        for join in joins {
            join.join()
                .expect("worker thread panicked")
                .expect("concurrent admission call failed");
        }

        assert!(
            crate::mxc_common::filesystem_dacl::validate_owner_only_directory(root.as_path())
                .expect("validate final root ACL")
        );
    }
}
