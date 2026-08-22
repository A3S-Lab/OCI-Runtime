//! containerd runtime-v2 entry point for A3S OCI Runtime.

#[cfg(unix)]
use std::io::{stdin, stdout, Read, Write};

#[cfg(unix)]
mod adapter;
#[cfg(unix)]
mod contract;
#[cfg(unix)]
mod identity;
#[cfg(unix)]
mod io;
#[cfg(unix)]
mod metadata;
#[cfg(unix)]
mod options;
#[cfg(unix)]
mod service;
#[cfg(unix)]
mod stats;

#[cfg(unix)]
use service::Service;

#[cfg(unix)]
fn main() {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let flags = match containerd_shim::parse(&arguments) {
        Ok(flags) => flags,
        Err(error) => {
            eprintln!(
                "{}: failed to parse shim arguments: {error}",
                contract::RUNTIME_TYPE
            );
            std::process::exit(1);
        }
    };
    if flags.version {
        write_version();
        return;
    }
    if flags.info {
        if let Err(error) = write_runtime_info() {
            eprintln!(
                "{}: failed to report runtime info: {error}",
                contract::RUNTIME_TYPE
            );
            std::process::exit(1);
        }
        return;
    }
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!(
                "{}: failed to start Tokio runtime: {error}",
                contract::RUNTIME_TYPE
            );
            std::process::exit(1);
        }
    };
    let config = containerd_shim::Config {
        no_reaper: true,
        no_sub_reaper: true,
        ..Default::default()
    };
    runtime.block_on(containerd_shim::asynchronous::run::<Service>(
        contract::RUNTIME_TYPE,
        Some(config),
    ));
}

#[cfg(unix)]
fn write_version() {
    println!("{}:", contract::SHIM_BINARY);
    println!("  Runtime: {}", contract::RUNTIME_TYPE);
    println!("  Version: {}", env!("CARGO_PKG_VERSION"));
    println!("  Contract: {}", contract::CONTRACT_VERSION);
    println!("  Task API: {}", contract::TASK_API_SERVICE);
    println!(
        "  Package: {}/{}",
        contract::SHIM_INSTALL_DIRECTORY,
        contract::SHIM_BINARY
    );
    println!("  Identity: {}", contract::IDENTITY_ENCODING);
    println!("  Generation: {}", contract::GENERATION_MAPPING);
    println!("  Task methods:");
    for method in contract::TASK_METHODS {
        println!("    {}: {}", method.name, method.status.label());
    }
    println!("  Compatibility:");
    for claim in contract::COMPATIBILITY_MATRIX {
        println!(
            "    {} | {} | {} | {}",
            claim.containerd,
            claim.host,
            claim.profile,
            claim.status.label()
        );
    }
}

#[cfg(unix)]
fn write_runtime_info() -> Result<(), String> {
    let mut request = Vec::new();
    stdin()
        .take(1024 * 1024 + 1)
        .read_to_end(&mut request)
        .map_err(|error| format!("read RuntimeInfo request: {error}"))?;
    if request.len() > 1024 * 1024 {
        return Err("RuntimeInfo request exceeds the 1 MiB limit".to_string());
    }
    let endpoint = std::env::var(contract::RUNTIME_ENDPOINT_ENV)
        .or_else(|_| std::env::var(contract::LEGACY_RUNTIME_ENDPOINT_ENV))
        .unwrap_or_else(|_| contract::DEFAULT_UNIX_ENDPOINT.to_string());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("start RuntimeInfo client runtime: {error}"))?;
    let features = runtime.block_on(async {
        let endpoint = a3s_oci_sdk::LocalIpcEndpoint::unix_socket(&endpoint)
            .map_err(|error| error.to_string())?;
        let client = a3s_oci_sdk::RuntimeClient::connect(&endpoint)
            .await
            .map_err(|error| error.to_string())?;
        client.features().await.map_err(|error| error.to_string())
    })?;
    let feature_json = serde_json::to_vec(&features.oci)
        .map_err(|error| format!("encode OCI Features JSON: {error}"))?;
    let encoded = encode_runtime_info(&feature_json, &endpoint)?;
    stdout()
        .write_all(&encoded)
        .and_then(|()| stdout().flush())
        .map_err(|error| format!("write RuntimeInfo: {error}"))
}

#[cfg(unix)]
fn encode_runtime_info(feature_json: &[u8], endpoint: &str) -> Result<Vec<u8>, String> {
    use containerd_shim_protos::protobuf::{Message, MessageField};
    use containerd_shim_protos::types::introspection::{RuntimeInfo, RuntimeVersion};

    let mut annotations = std::collections::HashMap::new();
    annotations.insert(
        "dev.a3s.oci.runtime-type".to_string(),
        contract::RUNTIME_TYPE.to_string(),
    );
    annotations.insert("dev.a3s.oci.sdk-endpoint".to_string(), endpoint.to_string());
    annotations.insert(
        "dev.a3s.oci.containerd-contract-version".to_string(),
        contract::CONTRACT_VERSION.to_string(),
    );
    annotations.insert(
        "dev.a3s.oci.containerd-task-api".to_string(),
        contract::TASK_API_SERVICE.to_string(),
    );
    annotations.insert(
        "dev.a3s.oci.identity-encoding".to_string(),
        contract::IDENTITY_ENCODING.to_string(),
    );
    annotations.insert(
        "dev.a3s.oci.generation-mapping".to_string(),
        contract::GENERATION_MAPPING.to_string(),
    );
    let qualified = &contract::DEVELOPMENT_QUALIFICATION;
    annotations.insert(
        "dev.a3s.oci.containerd-development-qualification".to_string(),
        format!(
            "{};{};{};{}",
            qualified.containerd,
            qualified.host,
            qualified.profile,
            qualified.status.label()
        ),
    );
    let features = containerd_shim_protos::protobuf::well_known_types::any::Any {
        type_url: contract::OCI_FEATURES_TYPE_URL.to_string(),
        value: feature_json.to_vec(),
        ..Default::default()
    };
    let info = RuntimeInfo {
        name: contract::SHIM_BINARY.to_string(),
        version: MessageField::some(RuntimeVersion {
            version: env!("CARGO_PKG_VERSION").to_string(),
            revision: option_env!("A3S_OCI_GIT_REVISION")
                .unwrap_or_default()
                .to_string(),
            ..Default::default()
        }),
        features: MessageField::some(features),
        annotations,
        ..Default::default()
    };
    info.write_to_bytes()
        .map_err(|error| format!("encode RuntimeInfo: {error}"))
}

#[cfg(not(unix))]
fn main() {
    eprintln!(
        "containerd-shim-a3s-oci-v2 is currently supported on Unix hosts; this build does not advertise a Windows runtime-v2 service"
    );
    std::process::exit(1);
}

#[cfg(all(test, unix))]
mod tests {
    use containerd_shim_protos::protobuf::Message;
    use containerd_shim_protos::types::introspection::RuntimeInfo;

    use super::*;

    #[test]
    fn runtime_info_is_a3s_identified_and_carries_oci_features() {
        let feature_json = br#"{"ociVersionMin":"1.0.2","ociVersionMax":"1.3.0"}"#;
        let encoded = encode_runtime_info(feature_json, contract::DEFAULT_UNIX_ENDPOINT)
            .expect("encode RuntimeInfo");
        let info = RuntimeInfo::parse_from_bytes(&encoded).expect("decode RuntimeInfo");

        assert_eq!(info.name(), contract::SHIM_BINARY);
        assert_eq!(info.version().version(), env!("CARGO_PKG_VERSION"));
        assert_eq!(
            info.annotations()["dev.a3s.oci.runtime-type"],
            contract::RUNTIME_TYPE
        );
        assert_eq!(
            info.annotations()["dev.a3s.oci.containerd-contract-version"],
            contract::CONTRACT_VERSION.to_string()
        );
        assert_eq!(
            info.annotations()["dev.a3s.oci.containerd-task-api"],
            contract::TASK_API_SERVICE
        );
        assert_eq!(
            info.annotations()["dev.a3s.oci.identity-encoding"],
            contract::IDENTITY_ENCODING
        );
        assert_eq!(info.features().type_url, contract::OCI_FEATURES_TYPE_URL);
        assert_eq!(info.features().value, feature_json);
    }
}
