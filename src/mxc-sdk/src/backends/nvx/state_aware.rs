// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use aci_edge_sandboxes::{AciEdgeSandbox, SandboxId};
use serde_json::Value;

use crate::mxc_common::models::{ExecutionRequest, MicroVmProvisionConfig};
use crate::mxc_common::mxc_error::MxcError;
use crate::mxc_common::state_aware_backend::{
    DeprovisionResult, ExecHandle, ExecStdio, ProvisionResult, StartResult, StatefulSandboxBackend,
    StopResult,
};

pub struct NvxStateAwareRunner {
    client: AciEdgeSandbox,
}

impl NvxStateAwareRunner {
    pub fn new() -> Result<Self, MxcError> {
        Ok(Self {
            client: super::runtime::create_client()?,
        })
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
            &self.client.capabilities(),
        )?;
        let result = self
            .client
            .provision_with(&provision, &spec)
            .map_err(super::runtime::map_nvx_error)?;
        Ok(ProvisionResult {
            sandbox_id: mxc_id(&result.sandbox_id),
            metadata: result.metadata.map(Value::Object),
        })
    }

    fn start(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<Self::StartConfig>,
    ) -> Result<StartResult<Self::StartMetadata>, MxcError> {
        self.client
            .start(&native_id(sandbox_id)?)
            .map_err(super::runtime::map_nvx_error)?;
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
        let request = super::policy::exec_request(request, piped, &self.client.capabilities())?;
        let execution = self
            .client
            .exec(&native_id(sandbox_id)?, &request)
            .map_err(super::runtime::map_nvx_error)?;
        super::process::into_exec_handle(execution)
    }

    fn stop(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<Self::StopConfig>,
    ) -> Result<StopResult<Self::StopMetadata>, MxcError> {
        self.client
            .stop(&native_id(sandbox_id)?)
            .map_err(super::runtime::map_nvx_error)?;
        Ok(StopResult { metadata: None })
    }

    fn deprovision(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<Self::DeprovisionConfig>,
    ) -> Result<DeprovisionResult<Self::DeprovisionMetadata>, MxcError> {
        self.client
            .deprovision(&native_id(sandbox_id)?)
            .map_err(super::runtime::map_nvx_error)?;
        Ok(DeprovisionResult { metadata: None })
    }

    fn validate_provision(
        &self,
        request: &ExecutionRequest,
        config: Option<&Self::ProvisionConfig>,
    ) -> Result<(), MxcError> {
        let (provision, spec) =
            super::policy::provision_request(request, config, &self.client.capabilities())?;
        self.client
            .validate_provision_with(&provision, &spec)
            .map_err(super::runtime::map_nvx_error)
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
        let request = super::policy::exec_request(request, false, &self.client.capabilities())?;
        self.client
            .validate_exec(&request)
            .map_err(super::runtime::map_nvx_error)
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
    SandboxId::from_token(token).map_err(super::runtime::map_nvx_error)
}

fn mxc_id(value: &SandboxId) -> String {
    format!("microvm:{}", value.token())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
