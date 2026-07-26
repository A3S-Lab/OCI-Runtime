use serde::Serialize;

/// Stable role assigned to one descriptor inherited by a native workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentInheritedDescriptorRole {
    /// A3S Box exec-protocol Unix listener.
    ExecListener,
    /// A3S Box PTY-protocol Unix listener.
    PtyListener,
    /// Dedicated A3S Box init diagnostic log.
    InitLog,
}

/// Kernel object type required for one inherited descriptor slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentInheritedDescriptorType {
    /// Bound, listening Unix stream socket.
    UnixStreamListener,
    /// Writable regular file.
    WritableRegularFile,
}

/// One stable logical descriptor slot without an ephemeral source descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AgentInheritedDescriptorSlot {
    /// Semantic role consumed by the configured init process.
    pub role: AgentInheritedDescriptorRole,
    /// Exact descriptor number exposed after exec.
    pub target: i32,
    /// Kernel object type required at the source descriptor.
    pub descriptor_type: AgentInheritedDescriptorType,
}

/// Stable logical attachment schema included in create idempotency fingerprints.
///
/// This schema deliberately excludes source descriptor numbers and filesystem
/// identities. A host process may reopen equivalent listeners and logs while
/// retrying a durable create after restart. Raw descriptors are transferred
/// only through the native in-process executor API and never through an agent
/// protocol frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentInheritedDescriptorSchema {
    /// Versioned attachment profile understood by the native executor.
    pub profile: String,
    /// Complete role, target, and kernel-object contract.
    pub slots: Vec<AgentInheritedDescriptorSlot>,
}

impl AgentInheritedDescriptorSchema {
    /// A3S Box host-sandbox control contract: exec, PTY, and init log on 3-5.
    #[must_use]
    pub fn a3s_box_control_v1() -> Self {
        Self {
            profile: "a3s-box-control-v1".to_string(),
            slots: vec![
                AgentInheritedDescriptorSlot {
                    role: AgentInheritedDescriptorRole::ExecListener,
                    target: 3,
                    descriptor_type: AgentInheritedDescriptorType::UnixStreamListener,
                },
                AgentInheritedDescriptorSlot {
                    role: AgentInheritedDescriptorRole::PtyListener,
                    target: 4,
                    descriptor_type: AgentInheritedDescriptorType::UnixStreamListener,
                },
                AgentInheritedDescriptorSlot {
                    role: AgentInheritedDescriptorRole::InitLog,
                    target: 5,
                    descriptor_type: AgentInheritedDescriptorType::WritableRegularFile,
                },
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AgentInheritedDescriptorRole, AgentInheritedDescriptorSchema, AgentInheritedDescriptorType,
    };

    #[test]
    fn a3s_box_schema_is_stable_and_contains_no_source_identity() {
        let schema = AgentInheritedDescriptorSchema::a3s_box_control_v1();
        assert_eq!(schema.profile, "a3s-box-control-v1");
        assert_eq!(schema.slots.len(), 3);
        assert_eq!(
            schema
                .slots
                .iter()
                .map(|slot| (slot.role, slot.target, slot.descriptor_type))
                .collect::<Vec<_>>(),
            vec![
                (
                    AgentInheritedDescriptorRole::ExecListener,
                    3,
                    AgentInheritedDescriptorType::UnixStreamListener,
                ),
                (
                    AgentInheritedDescriptorRole::PtyListener,
                    4,
                    AgentInheritedDescriptorType::UnixStreamListener,
                ),
                (
                    AgentInheritedDescriptorRole::InitLog,
                    5,
                    AgentInheritedDescriptorType::WritableRegularFile,
                ),
            ]
        );
        assert_eq!(
            serde_json::to_value(schema).expect("serialize descriptor schema"),
            serde_json::json!({
                "profile": "a3s-box-control-v1",
                "slots": [
                    {
                        "role": "exec-listener",
                        "target": 3,
                        "descriptor_type": "unix-stream-listener"
                    },
                    {
                        "role": "pty-listener",
                        "target": 4,
                        "descriptor_type": "unix-stream-listener"
                    },
                    {
                        "role": "init-log",
                        "target": 5,
                        "descriptor_type": "writable-regular-file"
                    }
                ]
            })
        );
    }
}
