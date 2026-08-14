//! containerd runtime-v2 entry point for A3S OCI Runtime.

#[cfg(unix)]
use std::io::{stdin, stdout, Read, Write};

#[cfg(unix)]
mod adapter;
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
const RUNTIME_TYPE: &str = "io.containerd.a3s-oci.v2";

#[cfg(unix)]
fn main() {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let flags = match containerd_shim::parse(&arguments) {
        Ok(flags) => flags,
        Err(error) => {
            eprintln!("{RUNTIME_TYPE}: failed to parse shim arguments: {error}");
            std::process::exit(1);
        }
    };
    if flags.version {
        println!("containerd-shim-a3s-oci-v2:");
        println!("  Runtime: {RUNTIME_TYPE}");
        println!("  Version: {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if flags.info {
        if let Err(error) = write_runtime_info() {
            eprintln!("{RUNTIME_TYPE}: failed to report runtime info: {error}");
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
            eprintln!("{RUNTIME_TYPE}: failed to start Tokio runtime: {error}");
            std::process::exit(1);
        }
    };
    let config = containerd_shim::Config {
        no_reaper: true,
        no_sub_reaper: true,
        ..Default::default()
    };
    runtime.block_on(containerd_shim::asynchronous::run::<Service>(
        RUNTIME_TYPE,
        Some(config),
    ));
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
    let endpoint = std::env::var("A3S_OCI_RUNTIME_ENDPOINT")
        .or_else(|_| std::env::var("A3S_OCI_RUNTIME_SOCKET"))
        .unwrap_or_else(|_| "/run/a3s-oci/runtime.sock".to_string());
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
        RUNTIME_TYPE.to_string(),
    );
    annotations.insert("dev.a3s.oci.sdk-endpoint".to_string(), endpoint.to_string());
    let features = containerd_shim_protos::protobuf::well_known_types::any::Any {
        type_url: "types.containerd.io/opencontainers/runtime-spec/1/features/Features".to_string(),
        value: feature_json.to_vec(),
        ..Default::default()
    };
    let info = RuntimeInfo {
        name: "containerd-shim-a3s-oci-v2".to_string(),
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
        let encoded = encode_runtime_info(feature_json, "/run/a3s-oci/runtime.sock")
            .expect("encode RuntimeInfo");
        let info = RuntimeInfo::parse_from_bytes(&encoded).expect("decode RuntimeInfo");

        assert_eq!(info.name(), "containerd-shim-a3s-oci-v2");
        assert_eq!(info.version().version(), env!("CARGO_PKG_VERSION"));
        assert_eq!(info.annotations()["dev.a3s.oci.runtime-type"], RUNTIME_TYPE);
        assert_eq!(
            info.features().type_url,
            "types.containerd.io/opencontainers/runtime-spec/1/features/Features"
        );
        assert_eq!(info.features().value, feature_json);
    }
}
