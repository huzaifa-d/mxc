// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use aci_edge_sandboxes::openvmm::{Artifacts, Hypervisor, OpenVmmConfig};
use aci_edge_sandboxes::AciEdgeSandbox;

use crate::mxc_common::mxc_error::{MxcError, MxcErrorCode};

pub(super) fn create_client() -> Result<AciEdgeSandbox, MxcError> {
    let artifacts = Artifacts::discover().map_err(map_nvx_error)?;
    let hypervisor = Hypervisor::from_env_or_default().map_err(map_nvx_error)?;
    let state_root = OpenVmmConfig::default_state_root().map_err(map_nvx_error)?;
    let config = OpenVmmConfig::from_artifacts(artifacts, hypervisor, state_root);
    AciEdgeSandbox::openvmm(config).map_err(map_nvx_error)
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
