// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;

use aci_edge_sandboxes::agent::{
    AgentBackend, AgentConfig, BundleSource, CpuProfile, ImageSettings, ReferenceSettings,
    RuntimeSource, SandboxDefaults, SetupConfig,
};
use aci_edge_sandboxes::{AciEdgeSandbox, Capabilities, ImageSource};

use crate::mxc_common::mxc_error::{MxcError, MxcErrorCode};

const BUNDLE_DIR_ENV: &str = "MXC_NVX_BUNDLE_DIR";
const STATE_ROOT_ENV: &str = "MXC_NVX_STATE_ROOT";
const LOCAL_APP_DATA_ENV: &str = "LOCALAPPDATA";
const IMAGE_REFERENCE: &str = "mcr.microsoft.com/azurelinux/base/core@sha256:c877612270d1ee2d6ab2bc1f64bfe38ab697ac50be325154ee5129fce89c17e4";
const RUNTIME_MANIFEST_SHA256: [u8; 32] = [
    0xf0, 0xb0, 0xa1, 0x9e, 0x31, 0x6d, 0x8b, 0x42, 0xa2, 0x62, 0xc0, 0xf8, 0x82, 0x18, 0xad, 0xb6,
    0xfb, 0xe1, 0xab, 0x45, 0x19, 0xf4, 0xff, 0x19, 0x05, 0x88, 0xcf, 0x3b, 0x1e, 0x4b, 0x36, 0x4b,
];
const AGENT_LIBRARY_SHA256: [u8; 32] = [
    0xba, 0x38, 0x37, 0xe2, 0x62, 0xb6, 0x84, 0x06, 0x89, 0x25, 0x6a, 0x67, 0x64, 0xa6, 0x4d, 0x50,
    0xc7, 0xdf, 0x84, 0x89, 0x36, 0x46, 0xbd, 0xb9, 0x24, 0xb3, 0x24, 0x1a, 0xa8, 0x35, 0x9b, 0x98,
];

trait Environment {
    fn value(&self, name: &str) -> Option<OsString>;
}

struct ProcessEnvironment;

impl Environment for ProcessEnvironment {
    fn value(&self, name: &str) -> Option<OsString> {
        std::env::var_os(name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeConfig {
    bundle_dir: PathBuf,
    state_root: PathBuf,
}

pub(super) fn create_client() -> Result<AciEdgeSandbox, MxcError> {
    create_client_with(&ProcessEnvironment)
}

fn create_client_with(environment: &impl Environment) -> Result<AciEdgeSandbox, MxcError> {
    let runtime = runtime_config(environment)?;
    let source = RuntimeSource::Bundle(BundleSource {
        path: runtime.bundle_dir.clone(),
        manifest_sha256: RUNTIME_MANIFEST_SHA256,
    });
    let setup = SetupConfig::new(runtime.state_root, source)
        .with_cpu_profile(CpuProfile::Auto)
        .with_defaults(
            SandboxDefaults::default()
                .with_image(ImageSource::Reference(IMAGE_REFERENCE.to_owned())),
        )
        .with_images(ImageSettings::default().with_references(ReferenceSettings::default()));
    let library = runtime.bundle_dir.join("bin").join("aci_edge_agent.dll");
    let backend = Arc::new(
        AgentBackend::new(AgentConfig::new(setup, library, AGENT_LIBRARY_SHA256))
            .map_err(map_nvx_error)?,
    );
    let client = AciEdgeSandbox::from_shared(backend);
    client.probe().map_err(map_nvx_error)?;
    require_phase_two_capabilities(&client.capabilities())?;
    Ok(client)
}

fn require_phase_two_capabilities(capabilities: &Capabilities) -> Result<(), MxcError> {
    if !capabilities.exec.command_line
        || !capabilities.exec.cwd
        || !capabilities.exec.env
        || capabilities.exec.clear_default_env
        || capabilities.exec.max_timeout_ms != Some(3_600_000)
    {
        return Err(MxcError::backend_unavailable(format!(
            "the signed NVX agent does not advertise the Phase 2 execution contract: {capabilities:#?}"
        )));
    }
    Ok(())
}

fn runtime_config(environment: &impl Environment) -> Result<RuntimeConfig, MxcError> {
    let bundle_dir = required_directory(environment, BUNDLE_DIR_ENV)?;
    for relative in [
        PathBuf::from("SOURCE-MANIFEST.json"),
        PathBuf::from("bin").join("aci_edge_agent.dll"),
    ] {
        if !bundle_dir.join(&relative).is_file() {
            return Err(MxcError::backend_unavailable(format!(
                "{BUNDLE_DIR_ENV} is missing required file {}",
                relative.display()
            )));
        }
    }

    let state_root = match non_empty_value(environment, STATE_ROOT_ENV) {
        Some(path) => absolute_path(PathBuf::from(path), STATE_ROOT_ENV)?,
        None => {
            let local_app_data =
                non_empty_value(environment, LOCAL_APP_DATA_ENV).ok_or_else(|| {
                    MxcError::backend_unavailable(format!(
                        "{STATE_ROOT_ENV} is unset and {LOCAL_APP_DATA_ENV} is unavailable"
                    ))
                })?;
            absolute_path(
                PathBuf::from(local_app_data)
                    .join("Microsoft")
                    .join("MXC")
                    .join("NVX"),
                LOCAL_APP_DATA_ENV,
            )?
        }
    };
    std::fs::create_dir_all(&state_root).map_err(|error| {
        MxcError::backend_unavailable(format!(
            "could not create NVX state root {}: {error}",
            state_root.display()
        ))
    })?;
    Ok(RuntimeConfig {
        bundle_dir,
        state_root,
    })
}

fn required_directory(environment: &impl Environment, name: &str) -> Result<PathBuf, MxcError> {
    let value = non_empty_value(environment, name).ok_or_else(|| {
        MxcError::backend_unavailable(format!(
            "{name} must name the manually extracted signed NVX bundle"
        ))
    })?;
    let path = absolute_path(PathBuf::from(value), name)?;
    if !path.is_dir() {
        return Err(MxcError::backend_unavailable(format!(
            "{name} does not name a directory: {}",
            path.display()
        )));
    }
    Ok(path)
}

fn non_empty_value(environment: &impl Environment, name: &str) -> Option<OsString> {
    environment.value(name).filter(|value| !value.is_empty())
}

fn absolute_path(path: PathBuf, name: &str) -> Result<PathBuf, MxcError> {
    std::path::absolute(path).map_err(|error| {
        MxcError::backend_unavailable(format!("could not resolve {name}: {error}"))
    })
}

pub(super) fn map_nvx_error(error: aci_edge_sandboxes::Error) -> MxcError {
    let code = match error.code() {
        aci_edge_sandboxes::ErrorCode::MalformedRequest => MxcErrorCode::MalformedRequest,
        aci_edge_sandboxes::ErrorCode::MalformedId => MxcErrorCode::MalformedId,
        aci_edge_sandboxes::ErrorCode::StaleId => MxcErrorCode::StaleId,
        aci_edge_sandboxes::ErrorCode::NotStarted => MxcErrorCode::NotStarted,
        aci_edge_sandboxes::ErrorCode::AlreadyStarted => MxcErrorCode::AlreadyStarted,
        aci_edge_sandboxes::ErrorCode::AlreadyStopped => MxcErrorCode::AlreadyStopped,
        aci_edge_sandboxes::ErrorCode::PolicyValidation => MxcErrorCode::PolicyValidation,
        aci_edge_sandboxes::ErrorCode::BackendUnavailable => MxcErrorCode::BackendUnavailable,
        aci_edge_sandboxes::ErrorCode::Unsupported
        | aci_edge_sandboxes::ErrorCode::BackendError => MxcErrorCode::BackendError,
        _ => MxcErrorCode::BackendError,
    };
    MxcError::new(code, error.message())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use tempfile::TempDir;

    use super::*;

    #[derive(Default)]
    struct TestEnvironment {
        values: HashMap<&'static str, OsString>,
    }

    impl TestEnvironment {
        fn with(mut self, name: &'static str, value: impl Into<OsString>) -> Self {
            self.values.insert(name, value.into());
            self
        }
    }

    impl Environment for TestEnvironment {
        fn value(&self, name: &str) -> Option<OsString> {
            self.values.get(name).cloned()
        }
    }

    fn bundle() -> TempDir {
        let directory = TempDir::new().unwrap();
        std::fs::write(directory.path().join("SOURCE-MANIFEST.json"), b"{}").unwrap();
        std::fs::create_dir(directory.path().join("bin")).unwrap();
        std::fs::write(
            directory.path().join("bin").join("aci_edge_agent.dll"),
            b"dll",
        )
        .unwrap();
        directory
    }

    #[test]
    fn runtime_config_requires_bundle_environment() {
        let error = runtime_config(&TestEnvironment::default()).unwrap_err();
        assert_eq!(error.code, MxcErrorCode::BackendUnavailable);
        assert!(error.message.contains(BUNDLE_DIR_ENV));
    }

    #[test]
    fn runtime_config_rejects_missing_bundle_files() {
        let bundle = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        let error = runtime_config(
            &TestEnvironment::default()
                .with(BUNDLE_DIR_ENV, bundle.path().as_os_str())
                .with(LOCAL_APP_DATA_ENV, local.path().as_os_str()),
        )
        .unwrap_err();
        assert!(error.message.contains("SOURCE-MANIFEST.json"));
    }

    #[test]
    fn runtime_config_uses_default_state_root() {
        let bundle = bundle();
        let local = TempDir::new().unwrap();
        let config = runtime_config(
            &TestEnvironment::default()
                .with(BUNDLE_DIR_ENV, bundle.path().as_os_str())
                .with(LOCAL_APP_DATA_ENV, local.path().as_os_str()),
        )
        .unwrap();
        assert_eq!(
            config.state_root,
            local.path().join("Microsoft").join("MXC").join("NVX")
        );
    }
}
