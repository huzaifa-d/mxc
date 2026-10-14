// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::path::{Component, PathBuf};

use aci_edge_sandboxes::{
    Access, Capabilities, EgressPolicy, ExecRequest, FilesystemPolicy, IngressPolicy, NetworkPeer,
    NetworkPolicy, NetworkPort, NetworkRule, Protocol, ProvisionRequest, SandboxSpec, StdinMode,
};

use crate::mxc_common::models::{
    ExecutionRequest, MicroVmProvisionConfig, NetworkAction, NetworkCidr,
    NetworkPeer as MxcNetworkPeer, NetworkPort as MxcNetworkPort, NetworkProtocol,
    NetworkRule as MxcNetworkRule,
};
use crate::mxc_common::mxc_error::MxcError;

const MAX_ENVIRONMENT_BYTES: usize = 32 * 1024;
const PROXY_ENVIRONMENT_KEYS: [&str; 4] = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"];

pub(super) fn provision_request(
    request: &ExecutionRequest,
    config: Option<&MicroVmProvisionConfig>,
    capabilities: &Capabilities,
) -> Result<(ProvisionRequest, SandboxSpec), MxcError> {
    validate_common(request)?;
    validate_provision_capabilities(request, config, capabilities)?;

    let mut provision = ProvisionRequest::new();
    if let Some(filesystem) = filesystem_policy(request) {
        provision = provision.with_filesystem(filesystem);
    }
    if let Some(network) = network_policy(request)? {
        provision = provision.with_network(network);
    }
    if let Some(proxy) = request.policy.network_proxy.address.as_ref() {
        provision = provision.with_network_proxy(proxy.to_url());
    }
    let spec = config
        .and_then(|config| config.memory_mib)
        .map_or_else(SandboxSpec::new, |memory| {
            SandboxSpec::new().with_memory_mib(memory)
        });
    Ok((provision, spec))
}

pub(super) fn exec_request(
    request: &ExecutionRequest,
    piped_stdin: bool,
    capabilities: &Capabilities,
) -> Result<ExecRequest, MxcError> {
    validate_common(request)?;
    if !capabilities.exec.command_line {
        return Err(unsupported("process.commandLine"));
    }
    if !request.working_directory.is_empty() && !capabilities.exec.cwd {
        return Err(unsupported("process.cwd"));
    }
    if request.env.is_some() && !capabilities.exec.env {
        return Err(unsupported("process.env"));
    }
    if piped_stdin && !capabilities.exec.stdin {
        return Err(unsupported("piped standard input"));
    }
    if let Some(max) = capabilities.exec.max_timeout_ms {
        if u64::from(request.script_timeout) > max {
            return Err(MxcError::policy_validation(format!(
                "NVX process.timeout must not exceed {max} ms"
            )));
        }
    }

    let mut exec = ExecRequest::command_line(request.script_code.clone())
        .with_inherit_default_env(request.inherit_default_env);
    if piped_stdin {
        exec = exec.with_stdin(StdinMode::Piped);
    }
    if request.script_timeout != 0 {
        exec = exec.with_timeout(std::time::Duration::from_millis(u64::from(
            request.script_timeout,
        )));
    }
    if !request.working_directory.is_empty() {
        exec = exec.with_cwd(request.working_directory.clone());
    }
    if let Some(environment) = &request.env {
        exec = exec.with_envs(environment.clone());
    }
    Ok(exec)
}

pub(super) fn validate_common(request: &ExecutionRequest) -> Result<(), MxcError> {
    if !request.policy.enumerate_paths.is_empty() {
        return Err(MxcError::policy_validation(
            "NVX does not support filesystem.enumeratePaths",
        ));
    }
    if request.policy.ui_specified {
        return Err(MxcError::policy_validation(
            "NVX does not support UI policy",
        ));
    }
    if request.policy.capture_denials.is_some() {
        return Err(MxcError::policy_validation(
            "NVX does not support processContainer.captureDenials",
        ));
    }
    if std::path::Path::new(&request.working_directory)
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(MxcError::policy_validation(
            "NVX process.cwd must not contain '..' path components",
        ));
    }
    if let Some(environment) = &request.env {
        if !request.inherit_default_env {
            return Err(MxcError::policy_validation(
                "NVX process.env requires inheritDefaultEnv=true",
            ));
        }
        let bytes = environment
            .iter()
            .map(|entry| entry.len().saturating_add(1))
            .sum::<usize>();
        if bytes > MAX_ENVIRONMENT_BYTES {
            return Err(MxcError::policy_validation(
                "NVX process.env must not exceed 32 KiB",
            ));
        }
        for entry in environment {
            let key = entry.split_once('=').map_or(entry.as_str(), |(key, _)| key);
            if PROXY_ENVIRONMENT_KEYS
                .iter()
                .any(|candidate| key.eq_ignore_ascii_case(candidate))
            {
                return Err(MxcError::policy_validation(
                    "NVX rejects proxy environment variables; use runtimeConfig.networkProxy",
                ));
            }
        }
    }
    Ok(())
}

fn validate_provision_capabilities(
    request: &ExecutionRequest,
    config: Option<&MicroVmProvisionConfig>,
    capabilities: &Capabilities,
) -> Result<(), MxcError> {
    let filesystem = &capabilities.filesystem;
    if !request.policy.readonly_paths.is_empty() && !filesystem.readonly_paths {
        return Err(unsupported("filesystem.readonlyPaths"));
    }
    if !request.policy.readwrite_paths.is_empty() && !filesystem.readwrite_paths {
        return Err(unsupported("filesystem.readwritePaths"));
    }
    if !request.policy.denied_paths.is_empty() && !filesystem.denied_paths {
        return Err(unsupported("filesystem.deniedPaths"));
    }

    if request.policy.runtime_network_proxy_specified
        && request.policy.network_proxy.is_enabled()
        && !capabilities.network.network_proxy
    {
        return Err(unsupported("runtimeConfig.networkProxy"));
    }
    if request.policy.network_specified {
        let egress = request.policy.network_egress.clone().unwrap_or_default();
        let ingress = request.policy.network_ingress.clone().unwrap_or_default();
        match egress.default {
            NetworkAction::Allow if !capabilities.network.egress_allow => {
                return Err(unsupported("network.egress.default=allow"));
            }
            NetworkAction::Deny if !capabilities.network.egress_deny => {
                return Err(unsupported("network.egress.default=deny"));
            }
            _ => {}
        }
        if (!egress.allow.is_empty() || !egress.deny.is_empty())
            && !capabilities.network.egress_rules
        {
            return Err(unsupported("network egress rules"));
        }
        match ingress.default {
            NetworkAction::Allow if !capabilities.network.ingress_allow => {
                return Err(unsupported("network.ingress.default=allow"));
            }
            NetworkAction::Deny if !capabilities.network.ingress_deny => {
                return Err(unsupported("network.ingress.default=deny"));
            }
            _ => {}
        }
        match ingress.host_loopback {
            NetworkAction::Allow if !capabilities.network.host_loopback_allow => {
                return Err(unsupported("network.ingress.hostLoopback=allow"));
            }
            NetworkAction::Deny if !capabilities.network.host_loopback_deny => {
                return Err(unsupported("network.ingress.hostLoopback=deny"));
            }
            _ => {}
        }
    }
    if config.and_then(|config| config.memory_mib).is_some() && !capabilities.spec.memory {
        return Err(unsupported("microvm.provision.memoryMib"));
    }
    Ok(())
}

fn filesystem_policy(request: &ExecutionRequest) -> Option<FilesystemPolicy> {
    let filesystem = FilesystemPolicy {
        readonly_paths: request
            .policy
            .readonly_paths
            .iter()
            .map(PathBuf::from)
            .collect(),
        readwrite_paths: request
            .policy
            .readwrite_paths
            .iter()
            .map(PathBuf::from)
            .collect(),
        denied_paths: request
            .policy
            .denied_paths
            .iter()
            .map(PathBuf::from)
            .collect(),
    };
    (!filesystem.is_empty()).then_some(filesystem)
}

fn network_policy(request: &ExecutionRequest) -> Result<Option<NetworkPolicy>, MxcError> {
    if !request.policy.network_specified {
        return Ok(None);
    }
    let egress = request.policy.network_egress.clone().unwrap_or_default();
    let ingress = request.policy.network_ingress.clone().unwrap_or_default();
    Ok(Some(NetworkPolicy {
        egress: EgressPolicy {
            default: access(egress.default),
            allow: egress.allow.iter().map(network_rule).collect(),
            deny: egress.deny.iter().map(network_rule).collect(),
        },
        ingress: IngressPolicy {
            default: access(ingress.default),
            host_loopback: Some(access(ingress.host_loopback)),
        },
    }))
}

fn access(action: NetworkAction) -> Access {
    match action {
        NetworkAction::Allow => Access::Allow,
        NetworkAction::Deny => Access::Deny,
    }
}

fn protocol(value: NetworkProtocol) -> Protocol {
    match value {
        NetworkProtocol::Tcp => Protocol::Tcp,
        NetworkProtocol::Udp => Protocol::Udp,
        NetworkProtocol::Icmp => Protocol::Icmp,
        NetworkProtocol::Any => Protocol::Any,
    }
}

fn cidr(value: &NetworkCidr) -> String {
    format!("{}/{}", value.address, value.prefix_length)
}

fn network_peer(peer: &MxcNetworkPeer) -> NetworkPeer {
    NetworkPeer {
        cidr: cidr(&peer.cidr),
        except: peer.except.iter().map(cidr).collect(),
    }
}

fn network_port(port: &MxcNetworkPort) -> NetworkPort {
    NetworkPort {
        protocol: protocol(port.protocol),
        port: port.port,
        end_port: port.end_port,
    }
}

fn network_rule(rule: &MxcNetworkRule) -> NetworkRule {
    NetworkRule {
        to: rule.to.iter().map(network_peer).collect(),
        ports: rule.ports.iter().map(network_port).collect(),
    }
}

fn unsupported(feature: &str) -> MxcError {
    MxcError::policy_validation(format!(
        "the configured NVX runtime does not support {feature}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_common::models::{NetworkEgressPolicy, NetworkIngressPolicy};

    fn request() -> ExecutionRequest {
        ExecutionRequest {
            script_code: "echo ok".to_owned(),
            ..ExecutionRequest::default()
        }
    }

    fn capabilities() -> Capabilities {
        let mut capabilities = Capabilities::new("agent");
        capabilities.exec.command_line = true;
        capabilities.exec.stdin = true;
        capabilities.exec.cancel = true;
        capabilities.exec.cwd = true;
        capabilities.exec.env = true;
        capabilities.exec.concurrent = true;
        capabilities.exec.max_timeout_ms = Some(3_600_000);
        capabilities.filesystem.readonly_paths = true;
        capabilities.filesystem.readwrite_paths = true;
        capabilities.filesystem.denied_paths = true;
        capabilities.network.egress_allow = true;
        capabilities.network.egress_deny = true;
        capabilities.network.ingress_deny = true;
        capabilities.network.host_loopback_deny = true;
        capabilities.network.egress_rules = true;
        capabilities.network.network_proxy = true;
        capabilities.spec.memory = true;
        capabilities
    }

    #[test]
    fn maps_filesystem_network_proxy_and_memory() {
        let mut request = request();
        request.policy.readonly_paths = vec![r"C:\ro".to_owned()];
        request.policy.readwrite_paths = vec![r"C:\rw".to_owned()];
        request.policy.denied_paths = vec![r"C:\rw\secret".to_owned()];
        request.policy.network_specified = true;
        request.policy.network_egress = Some(NetworkEgressPolicy::default());
        request.policy.network_ingress = Some(NetworkIngressPolicy::default());
        request.policy.runtime_network_proxy_specified = true;
        request.policy.network_proxy.address = Some(crate::mxc_common::models::ProxyAddress::new(
            "127.0.0.1".to_owned(),
            3128,
        ));
        let (provision, spec) = provision_request(
            &request,
            Some(&MicroVmProvisionConfig {
                memory_mib: Some(1024),
            }),
            &capabilities(),
        )
        .unwrap();
        assert_eq!(
            provision.filesystem.unwrap().readwrite_paths,
            vec![PathBuf::from(r"C:\rw")]
        );
        assert_eq!(
            provision
                .runtime_config
                .as_ref()
                .and_then(|runtime| runtime.network_proxy.as_deref()),
            Some("http://127.0.0.1:3128")
        );
        assert_eq!(
            spec.resources.and_then(|resources| resources.memory_mib),
            Some(1024)
        );
    }

    #[test]
    fn rejects_unadvertised_ingress_allow() {
        let mut request = request();
        request.policy.network_specified = true;
        request.policy.network_egress = Some(NetworkEgressPolicy::default());
        request.policy.network_ingress = Some(NetworkIngressPolicy {
            default: NetworkAction::Allow,
            host_loopback: NetworkAction::Deny,
        });
        let error = provision_request(&request, None, &capabilities()).unwrap_err();
        assert!(error.message.contains("ingress.default=allow"));
    }

    #[test]
    fn piped_exec_requires_stdin_capability() {
        let mut capabilities = capabilities();
        capabilities.exec.stdin = false;
        let error = exec_request(&request(), true, &capabilities).unwrap_err();
        assert!(error.message.contains("piped standard input"));
    }

    #[test]
    fn signed_profile_process_restrictions_fail_closed() {
        let mut cwd = request();
        cwd.working_directory = "/work/../escape".to_owned();
        assert!(exec_request(&cwd, false, &capabilities())
            .unwrap_err()
            .message
            .contains("must not contain '..'"));

        let mut replacement = request();
        replacement.env = Some(vec!["KEY=value".to_owned()]);
        assert!(exec_request(&replacement, false, &capabilities())
            .unwrap_err()
            .message
            .contains("inheritDefaultEnv=true"));

        let mut proxy = request();
        proxy.env = Some(vec!["Http_Proxy=http://proxy".to_owned()]);
        proxy.inherit_default_env = true;
        assert!(exec_request(&proxy, false, &capabilities())
            .unwrap_err()
            .message
            .contains("proxy environment"));

        let mut timeout = request();
        timeout.script_timeout = 3_600_001;
        assert!(exec_request(&timeout, false, &capabilities())
            .unwrap_err()
            .message
            .contains("3600000"));
    }
}
