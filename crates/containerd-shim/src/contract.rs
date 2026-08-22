//! Versioned containerd Runtime V2 compatibility and package contract.

pub(crate) const CONTRACT_VERSION: u32 = 1;
pub(crate) const RUNTIME_TYPE: &str = "io.containerd.a3s-oci.v2";
pub(crate) const SHIM_BINARY: &str = "containerd-shim-a3s-oci-v2";
pub(crate) const TASK_API_SERVICE: &str = "containerd.task.v2.Task";
pub(crate) const SHIM_INSTALL_DIRECTORY: &str = "/usr/local/bin";
pub(crate) const DEFAULT_UNIX_ENDPOINT: &str = "/run/a3s-oci/runtime.sock";
pub(crate) const RUNTIME_ENDPOINT_ENV: &str = "A3S_OCI_RUNTIME_ENDPOINT";
pub(crate) const LEGACY_RUNTIME_ENDPOINT_ENV: &str = "A3S_OCI_RUNTIME_SOCKET";

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
        status: MethodStatus::Unimplemented,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_api_surface_is_exact_and_checkpoint_is_the_only_gap() {
        assert_eq!(TASK_API_SERVICE, "containerd.task.v2.Task");
        assert_eq!(TASK_METHODS.len(), 17);
        assert_eq!(
            TASK_METHODS
                .iter()
                .filter(|method| method.status == MethodStatus::Implemented)
                .count(),
            16
        );
        assert_eq!(
            TASK_METHODS
                .iter()
                .filter(|method| method.status == MethodStatus::Unimplemented)
                .map(|method| method.name)
                .collect::<Vec<_>>(),
            ["Checkpoint"]
        );
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
        let release_binary = format!("target/release/{SHIM_BINARY}");
        let install_path = format!("{SHIM_INSTALL_DIRECTORY}/{SHIM_BINARY}");

        assert!(cargo_manifest.contains(&binary_declaration));
        assert!(release_workflow.contains("-p a3s-oci-containerd-shim"));
        assert!(release_workflow.contains(&release_binary));
        assert!(release_workflow.contains("docs/containerd-runtime-v2.md"));
        for document in [readme, documentation] {
            assert!(document.contains(RUNTIME_TYPE));
            assert!(document.contains(SHIM_BINARY));
            assert!(document.contains(TASK_API_SERVICE));
            assert!(document.contains(&install_path));
            assert!(document.contains(IDENTITY_ENCODING));
        }
    }
}
