//! Versioned containerd Runtime V2 compatibility and package contract.

use std::collections::BTreeSet;

use a3s_oci_sdk::RuntimeOperation;

pub(crate) const CONTRACT_VERSION: u32 = 1;
pub(crate) const RUNTIME_TYPE: &str = "io.containerd.a3s-oci.v2";
pub(crate) const SHIM_BINARY: &str = "containerd-shim-a3s-oci-v2";
pub(crate) const TASK_API_SERVICE: &str = "containerd.task.v2.Task";
pub(crate) const SHIM_INSTALL_DIRECTORY: &str = "/usr/local/bin";
pub(crate) const DEFAULT_UNIX_ENDPOINT: &str = "/run/a3s-oci/runtime.sock";
pub(crate) const RUNTIME_ENDPOINT_ENV: &str = "A3S_OCI_RUNTIME_ENDPOINT";
pub(crate) const LEGACY_RUNTIME_ENDPOINT_ENV: &str = "A3S_OCI_RUNTIME_SOCKET";
pub(crate) const SDK_OPERATIONS_ANNOTATION: &str = "dev.a3s.oci.containerd-sdk-operations";

pub(crate) const OCI_FEATURES_TYPE_URL: &str =
    "types.containerd.io/opencontainers/runtime-spec/1/features/Features";
pub(crate) const OCI_PROCESS_TYPE_URL: &str =
    "types.containerd.io/opencontainers/runtime-spec/1/Process";
pub(crate) const OCI_LINUX_RESOURCES_TYPE_URL: &str =
    "types.containerd.io/opencontainers/runtime-spec/1/LinuxResources";
pub(crate) const CREATE_OPTIONS_TYPE_URL: &str = "dev.a3s.oci.runtime.v1.CreateOptions";
pub(crate) const CREATE_OPTIONS_SCHEMA_VERSION: u32 = 1;

pub(crate) const IDENTITY_ENCODING: &str = "sha256-length-framed-u64be-v1";
pub(crate) const GENERATION_MAPPING: &str = "runtime-assigned-monotonic-exact";
pub(crate) const CONTAINER_ID_PREFIX: &str = "ctrd-";
pub(crate) const PROCESS_ID_PREFIX: &str = "exec-";
pub(crate) const OPERATION_ID_PREFIX: &str = "ctrd-op-";
pub(crate) const TASK_INCARNATION_BYTES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QualificationStatus {
    DevelopmentQualified,
    NotQualified,
}

impl QualificationStatus {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::DevelopmentQualified => "development-qualified",
            Self::NotQualified => "not-qualified",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CompatibilityClaim {
    pub(crate) containerd: &'static str,
    pub(crate) host: &'static str,
    pub(crate) profile: &'static str,
    pub(crate) status: QualificationStatus,
}

pub(crate) const DEVELOPMENT_QUALIFICATION: CompatibilityClaim = CompatibilityClaim {
    containerd: "2.2.2",
    host: "ubuntu-linux-arm64",
    profile: "shared-host-kernel",
    status: QualificationStatus::DevelopmentQualified,
};

pub(crate) const COMPATIBILITY_MATRIX: &[CompatibilityClaim] = &[
    DEVELOPMENT_QUALIFICATION,
    CompatibilityClaim {
        containerd: "2.0.x,2.1.x,other-2.2.x",
        host: "linux",
        profile: "any",
        status: QualificationStatus::NotQualified,
    },
    CompatibilityClaim {
        containerd: "1.7.x-and-earlier",
        host: "linux",
        profile: "any",
        status: QualificationStatus::NotQualified,
    },
    CompatibilityClaim {
        containerd: "any",
        host: "linux",
        profile: "dedicated-vm",
        status: QualificationStatus::NotQualified,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MethodStatus {
    Implemented,
    Unimplemented,
}

impl MethodStatus {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Implemented => "implemented",
            Self::Unimplemented => "unimplemented",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TaskMethod {
    pub(crate) name: &'static str,
    pub(crate) status: MethodStatus,
}

pub(crate) const TASK_METHODS: &[TaskMethod] = &[
    TaskMethod {
        name: "State",
        status: MethodStatus::Implemented,
    },
    TaskMethod {
        name: "Create",
        status: MethodStatus::Implemented,
    },
    TaskMethod {
        name: "Start",
        status: MethodStatus::Implemented,
    },
    TaskMethod {
        name: "Delete",
        status: MethodStatus::Implemented,
    },
    TaskMethod {
        name: "Pids",
        status: MethodStatus::Implemented,
    },
    TaskMethod {
        name: "Pause",
        status: MethodStatus::Implemented,
    },
    TaskMethod {
        name: "Resume",
        status: MethodStatus::Implemented,
    },
    TaskMethod {
        name: "Checkpoint",
        status: MethodStatus::Implemented,
    },
    TaskMethod {
        name: "Kill",
        status: MethodStatus::Implemented,
    },
    TaskMethod {
        name: "Exec",
        status: MethodStatus::Implemented,
    },
    TaskMethod {
        name: "ResizePty",
        status: MethodStatus::Implemented,
    },
    TaskMethod {
        name: "CloseIO",
        status: MethodStatus::Implemented,
    },
    TaskMethod {
        name: "Update",
        status: MethodStatus::Implemented,
    },
    TaskMethod {
        name: "Wait",
        status: MethodStatus::Implemented,
    },
    TaskMethod {
        name: "Stats",
        status: MethodStatus::Implemented,
    },
    TaskMethod {
        name: "Connect",
        status: MethodStatus::Implemented,
    },
    TaskMethod {
        name: "Shutdown",
        status: MethodStatus::Implemented,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SdkTranslation {
    pub(crate) source: &'static str,
    pub(crate) task_method: Option<&'static str>,
    pub(crate) sdk_operations: &'static [RuntimeOperation],
    pub(crate) admission: SdkAdmission,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SdkAdmission {
    Required,
    Optional,
}

pub(crate) const SDK_TRANSLATIONS: &[SdkTranslation] = &[
    SdkTranslation {
        source: "Create",
        task_method: Some("Create"),
        sdk_operations: &[RuntimeOperation::Create],
        admission: SdkAdmission::Required,
    },
    SdkTranslation {
        source: "Create(restore)",
        task_method: Some("Create"),
        sdk_operations: &[RuntimeOperation::Restore],
        admission: SdkAdmission::Optional,
    },
    SdkTranslation {
        source: "Start(init)",
        task_method: Some("Start"),
        sdk_operations: &[RuntimeOperation::Start],
        admission: SdkAdmission::Required,
    },
    SdkTranslation {
        source: "Start(exec)",
        task_method: Some("Start"),
        sdk_operations: &[RuntimeOperation::Processes, RuntimeOperation::Exec],
        admission: SdkAdmission::Required,
    },
    SdkTranslation {
        source: "State(init-or-exec)",
        task_method: Some("State"),
        sdk_operations: &[RuntimeOperation::State],
        admission: SdkAdmission::Required,
    },
    SdkTranslation {
        source: "Exec(stage)",
        task_method: Some("Exec"),
        sdk_operations: &[],
        admission: SdkAdmission::Required,
    },
    SdkTranslation {
        source: "Wait(init)",
        task_method: Some("Wait"),
        sdk_operations: &[RuntimeOperation::Wait],
        admission: SdkAdmission::Required,
    },
    SdkTranslation {
        source: "Wait(exec)",
        task_method: Some("Wait"),
        sdk_operations: &[RuntimeOperation::WaitProcess],
        admission: SdkAdmission::Required,
    },
    SdkTranslation {
        source: "Kill(init)",
        task_method: Some("Kill"),
        sdk_operations: &[RuntimeOperation::Kill],
        admission: SdkAdmission::Required,
    },
    SdkTranslation {
        source: "Kill(exec)",
        task_method: Some("Kill"),
        sdk_operations: &[RuntimeOperation::SignalProcess],
        admission: SdkAdmission::Required,
    },
    SdkTranslation {
        source: "Delete(init)",
        task_method: Some("Delete"),
        sdk_operations: &[RuntimeOperation::Delete],
        admission: SdkAdmission::Required,
    },
    SdkTranslation {
        source: "Delete(exec)",
        task_method: Some("Delete"),
        sdk_operations: &[],
        admission: SdkAdmission::Required,
    },
    SdkTranslation {
        source: "Pids",
        task_method: Some("Pids"),
        sdk_operations: &[RuntimeOperation::Processes],
        admission: SdkAdmission::Required,
    },
    SdkTranslation {
        source: "Pause",
        task_method: Some("Pause"),
        sdk_operations: &[RuntimeOperation::Pause],
        admission: SdkAdmission::Required,
    },
    SdkTranslation {
        source: "Resume",
        task_method: Some("Resume"),
        sdk_operations: &[RuntimeOperation::Resume],
        admission: SdkAdmission::Required,
    },
    SdkTranslation {
        source: "Checkpoint",
        task_method: Some("Checkpoint"),
        sdk_operations: &[RuntimeOperation::Checkpoint],
        admission: SdkAdmission::Optional,
    },
    SdkTranslation {
        source: "Update",
        task_method: Some("Update"),
        sdk_operations: &[RuntimeOperation::Update],
        admission: SdkAdmission::Required,
    },
    SdkTranslation {
        source: "ResizePty",
        task_method: Some("ResizePty"),
        sdk_operations: &[RuntimeOperation::Resize],
        admission: SdkAdmission::Required,
    },
    SdkTranslation {
        source: "CloseIO",
        task_method: Some("CloseIO"),
        sdk_operations: &[RuntimeOperation::CloseStdin],
        admission: SdkAdmission::Required,
    },
    SdkTranslation {
        source: "Stats",
        task_method: Some("Stats"),
        sdk_operations: &[RuntimeOperation::Stats],
        admission: SdkAdmission::Required,
    },
    SdkTranslation {
        source: "Connect",
        task_method: Some("Connect"),
        sdk_operations: &[],
        admission: SdkAdmission::Required,
    },
    SdkTranslation {
        source: "Shutdown",
        task_method: Some("Shutdown"),
        sdk_operations: &[],
        admission: SdkAdmission::Required,
    },
    SdkTranslation {
        source: "stdin-pump",
        task_method: None,
        sdk_operations: &[
            RuntimeOperation::WriteStdin,
            RuntimeOperation::CloseStdin,
            RuntimeOperation::Processes,
        ],
        admission: SdkAdmission::Required,
    },
    SdkTranslation {
        source: "output-pump",
        task_method: None,
        sdk_operations: &[RuntimeOperation::ReadOutput],
        admission: SdkAdmission::Required,
    },
];

pub(crate) fn required_sdk_operations() -> Vec<RuntimeOperation> {
    SDK_TRANSLATIONS
        .iter()
        .filter(|translation| translation.admission == SdkAdmission::Required)
        .flat_map(|translation| translation.sdk_operations.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
pub(crate) fn optional_sdk_operations() -> Vec<RuntimeOperation> {
    SDK_TRANSLATIONS
        .iter()
        .filter(|translation| translation.admission == SdkAdmission::Optional)
        .flat_map(|translation| translation.sdk_operations.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub(crate) const fn sdk_operation_name(operation: RuntimeOperation) -> &'static str {
    match operation {
        RuntimeOperation::Create => "create",
        RuntimeOperation::State => "state",
        RuntimeOperation::Start => "start",
        RuntimeOperation::Kill => "kill",
        RuntimeOperation::Delete => "delete",
        RuntimeOperation::Exec => "exec",
        RuntimeOperation::Wait => "wait",
        RuntimeOperation::Pause => "pause",
        RuntimeOperation::Resume => "resume",
        RuntimeOperation::Update => "update",
        RuntimeOperation::Processes => "processes",
        RuntimeOperation::Stats => "stats",
        RuntimeOperation::ReadOutput => "read-output",
        RuntimeOperation::WriteStdin => "write-stdin",
        RuntimeOperation::CloseStdin => "close-stdin",
        RuntimeOperation::Resize => "resize",
        RuntimeOperation::SignalProcess => "signal-process",
        RuntimeOperation::WaitProcess => "wait-process",
        RuntimeOperation::Checkpoint => "checkpoint",
        RuntimeOperation::Restore => "restore",
        _ => "outside-containerd-contract",
    }
}

pub(crate) fn sdk_operation_names(operations: &[RuntimeOperation]) -> String {
    operations
        .iter()
        .copied()
        .map(sdk_operation_name)
        .collect::<Vec<_>>()
        .join(",")
}

pub(crate) fn sdk_translation_action(translation: &SdkTranslation) -> String {
    if !translation.sdk_operations.is_empty() {
        let operations = sdk_operation_names(translation.sdk_operations);
        return match translation.admission {
            SdkAdmission::Required => operations,
            SdkAdmission::Optional => format!("optional:{operations}"),
        };
    }

    let is_unimplemented = translation
        .task_method
        .and_then(|name| TASK_METHODS.iter().find(|method| method.name == name))
        .map(|method| method.status == MethodStatus::Unimplemented)
        .unwrap_or(false);
    if is_unimplemented {
        "unimplemented".to_string()
    } else {
        "local-only".to_string()
    }
}

#[cfg(test)]
mod compatibility_record;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_api_surface_is_fully_implemented() {
        assert_eq!(TASK_API_SERVICE, "containerd.task.v2.Task");
        assert_eq!(TASK_METHODS.len(), 17);
        assert_eq!(
            TASK_METHODS
                .iter()
                .filter(|method| method.status == MethodStatus::Implemented)
                .count(),
            17
        );
        assert_eq!(
            TASK_METHODS
                .iter()
                .filter(|method| method.status == MethodStatus::Unimplemented)
                .map(|method| method.name)
                .collect::<Vec<_>>(),
            Vec::<&str>::new()
        );
    }

    #[test]
    fn sdk_translation_routes_cover_every_task_method_and_exact_required_operations() {
        let methods = TASK_METHODS
            .iter()
            .map(|method| method.name)
            .collect::<BTreeSet<_>>();
        let routed_methods = SDK_TRANSLATIONS
            .iter()
            .filter_map(|translation| translation.task_method)
            .collect::<BTreeSet<_>>();

        assert_eq!(SDK_TRANSLATIONS.len(), 24);
        assert_eq!(routed_methods, methods);
        assert_eq!(
            required_sdk_operations(),
            vec![
                RuntimeOperation::Create,
                RuntimeOperation::State,
                RuntimeOperation::Start,
                RuntimeOperation::Kill,
                RuntimeOperation::Delete,
                RuntimeOperation::Exec,
                RuntimeOperation::Wait,
                RuntimeOperation::Pause,
                RuntimeOperation::Resume,
                RuntimeOperation::Update,
                RuntimeOperation::Processes,
                RuntimeOperation::Stats,
                RuntimeOperation::ReadOutput,
                RuntimeOperation::WriteStdin,
                RuntimeOperation::CloseStdin,
                RuntimeOperation::Resize,
                RuntimeOperation::SignalProcess,
                RuntimeOperation::WaitProcess,
            ]
        );
        assert!(required_sdk_operations()
            .into_iter()
            .all(|operation| sdk_operation_name(operation) != "outside-containerd-contract"));
        assert_eq!(
            optional_sdk_operations(),
            vec![RuntimeOperation::Checkpoint, RuntimeOperation::Restore]
        );
        assert_eq!(
            SDK_TRANSLATIONS
                .iter()
                .filter(|translation| sdk_translation_action(translation) == "local-only")
                .map(|translation| translation.source)
                .collect::<Vec<_>>(),
            ["Exec(stage)", "Delete(exec)", "Connect", "Shutdown"]
        );
        assert!(SDK_TRANSLATIONS
            .iter()
            .all(|translation| sdk_translation_action(translation) != "unimplemented"));
    }

    #[test]
    fn compatibility_claim_is_exact_and_does_not_promote_a_range() {
        let qualified = COMPATIBILITY_MATRIX
            .iter()
            .filter(|claim| claim.status == QualificationStatus::DevelopmentQualified)
            .collect::<Vec<_>>();

        assert_eq!(qualified.len(), 1);
        assert_eq!(qualified, [&DEVELOPMENT_QUALIFICATION]);
    }

    #[test]
    fn cargo_release_and_documentation_mirror_the_code_owned_contract() {
        let cargo_manifest = include_str!("../Cargo.toml");
        let release_workflow = include_str!("../../../.github/workflows/release.yml");
        let readme = include_str!("../../../README.md");
        let documentation = include_str!("../../../docs/containerd-runtime-v2.md");
        let binary_declaration = format!("name = \"{SHIM_BINARY}\"");
        let release_binary = format!("$release/{SHIM_BINARY}");
        let install_path = format!("{SHIM_INSTALL_DIRECTORY}/{SHIM_BINARY}");

        assert!(cargo_manifest.contains(&binary_declaration));
        assert!(cargo_manifest.contains("a3s-oci-sdk ="));
        for forbidden_dependency in [
            "a3s-oci-runtime",
            "a3s-oci-core",
            "a3s-oci-agent",
            "a3s-box",
        ] {
            assert!(!cargo_manifest.contains(forbidden_dependency));
        }
        assert!(release_workflow.contains("a3s-oci-containerd-shim"));
        assert!(release_workflow.contains("build-static-musl.sh"));
        assert!(release_workflow.contains("verify-static-elf.sh"));
        assert!(release_workflow.contains(&release_binary));
        assert!(release_workflow.contains("docs/containerd-runtime-v2.md"));
        assert!(release_workflow.contains("compat/containerd-runtime-v2.json"));
        assert!(documentation.contains("compat/containerd-runtime-v2.json"));
        assert!(documentation.contains(SDK_OPERATIONS_ANNOTATION));
        for document in [readme, documentation] {
            assert!(document.contains(RUNTIME_TYPE));
            assert!(document.contains(SHIM_BINARY));
            assert!(document.contains(TASK_API_SERVICE));
            assert!(document.contains(&install_path));
            assert!(document.contains(IDENTITY_ENCODING));
        }
    }
}
