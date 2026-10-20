// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::path::Path;

use aci_edge_sandboxes::agent::AgentConfig;
use aci_edge_sandboxes::AciEdgeSandbox;
use aci_edge_sandboxes::{ImageSource, SandboxSpec};

use crate::mxc_common::mxc_error::{MxcError, MxcErrorCode};

pub(super) fn create_client(state_root: &Path) -> Result<AciEdgeSandbox, MxcError> {
    let config = AgentConfig::bundled(state_root).map_err(map_nvx_error)?;
    AciEdgeSandbox::agent(config).map_err(map_nvx_error)
}

pub(super) fn sandbox_spec(image: &str) -> Result<SandboxSpec, MxcError> {
    crate::mxc_contract::dev::ImageReference::validate(image)
        .map_err(MxcError::malformed_request)?;
    Ok(SandboxSpec::new().with_image(ImageSource::Reference(image.to_owned())))
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
        _ => MxcErrorCode::BackendError,
    };
    MxcError::new(
        code,
        format!("NVX signed bundled agent: {}", error.message()),
    )
}
