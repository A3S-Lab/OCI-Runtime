use std::path::Path;

use a3s_oci_sdk::Result;

use super::{audit_error, entry_name, json_stem, transaction_stem};
use crate::state::DurableStateStore;

impl DurableStateStore {
    pub(super) async fn audit_event_entries(&self) -> Result<()> {
        let events = self.root.join("events");
        for entry in self
            .filesystem
            .read_directory(&events, "runtime event directory")
            .await?
        {
            let name = entry_name(entry, "audit-runtime-events", "runtime event directory")?;
            let path = events.join(&name);
            match name.as_str() {
                "sequence.json" | ".sequence.json.next" => {
                    self.filesystem
                        .ensure_plain_file(&path, "runtime event cursor file")
                        .await?;
                }
                "keys" | "records" => {
                    self.filesystem
                        .ensure_plain_directory(&path, "runtime event layout directory")
                        .await?;
                }
                _ => {
                    return Err(audit_error(
                        "audit-runtime-events",
                        format!("runtime event directory contains unexpected entry {name:?}"),
                    ));
                }
            }
        }
        self.audit_event_leaf_entries(&events.join("keys"), EventLeaf::Claim)
            .await?;
        self.audit_event_leaf_entries(&events.join("records"), EventLeaf::Record)
            .await?;
        self.audit_event_journal().await
    }

    async fn audit_event_leaf_entries(&self, directory: &Path, kind: EventLeaf) -> Result<()> {
        for entry in self
            .filesystem
            .read_directory(directory, "runtime event leaf directory")
            .await?
        {
            let name = entry_name(
                entry,
                "audit-runtime-events",
                "runtime event leaf directory",
            )?;
            let (stem, transaction) = match transaction_stem(&name) {
                Some(stem) => (stem, true),
                None => (
                    json_stem(&name, "audit-runtime-events", "runtime event record")?,
                    false,
                ),
            };
            if !kind.valid_stem(stem) {
                return Err(audit_error(
                    "audit-runtime-events",
                    format!("runtime event directory contains invalid entry {name:?}"),
                ));
            }
            self.filesystem
                .ensure_plain_file(
                    &directory.join(&name),
                    if transaction {
                        "runtime event transaction file"
                    } else {
                        "runtime event record file"
                    },
                )
                .await?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum EventLeaf {
    Claim,
    Record,
}

impl EventLeaf {
    fn valid_stem(self, stem: &str) -> bool {
        match self {
            Self::Claim => {
                stem.len() == 64
                    && stem
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            }
            Self::Record => stem.len() == 20 && stem.bytes().all(|byte| byte.is_ascii_digit()),
        }
    }
}
