use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tempfile::TempDir;

use super::{schema_key, ResctrlFilesystem, RESCTRL_MON_GROUPS, RESCTRL_SCHEMATA, RESCTRL_TASKS};

#[derive(Debug, Clone, Default)]
pub(super) struct FixtureFilesystem {
    operations: Arc<Mutex<Vec<String>>>,
    reject_monitoring: Arc<AtomicBool>,
}

impl FixtureFilesystem {
    pub(super) fn operations(&self) -> Vec<String> {
        self.operations.lock().expect("operation log").clone()
    }

    fn record(&self, operation: impl Into<String>) {
        self.operations
            .lock()
            .expect("operation log")
            .push(operation.into());
    }

    pub(super) fn reject_next_monitoring_group(&self) {
        self.reject_monitoring.store(true, Ordering::SeqCst);
    }

    fn materialize_control(path: &std::path::Path) -> std::io::Result<()> {
        std::fs::write(path.join(RESCTRL_TASKS), b"")?;
        std::fs::write(path.join(RESCTRL_SCHEMATA), b"")?;
        std::fs::create_dir(path.join(RESCTRL_MON_GROUPS))
    }
}

impl ResctrlFilesystem for FixtureFilesystem {
    fn create_control_group(&self, path: &std::path::Path) -> std::io::Result<()> {
        self.record(format!("create-control:{}", path.display()));
        std::fs::create_dir(path)?;
        Self::materialize_control(path)
    }

    fn create_monitoring_group(&self, path: &std::path::Path) -> std::io::Result<()> {
        self.record(format!("create-monitor:{}", path.display()));
        if self.reject_monitoring.swap(false, Ordering::SeqCst) {
            return Err(std::io::Error::other("fixture monitoring limit reached"));
        }
        std::fs::create_dir(path)?;
        std::fs::write(path.join(RESCTRL_TASKS), b"")
    }

    fn write_schemata(&self, group: &std::path::Path, lines: &[String]) -> std::io::Result<()> {
        self.record(format!("write-schemata:{}", lines.join("|")));
        let current = std::fs::read_to_string(group.join(RESCTRL_SCHEMATA))?;
        let mut values = super::schema_map(current.lines());
        for line in lines {
            values.insert(schema_key(line).to_string(), line.clone());
        }
        let mut encoded = values.into_values().collect::<Vec<_>>().join("\n");
        if !encoded.is_empty() {
            encoded.push('\n');
        }
        std::fs::write(group.join(RESCTRL_SCHEMATA), encoded)
    }

    fn read_schemata(&self, group: &std::path::Path) -> std::io::Result<String> {
        std::fs::read_to_string(group.join(RESCTRL_SCHEMATA))
    }

    fn write_task(&self, group: &std::path::Path, pid: i32) -> std::io::Result<()> {
        self.record(format!("write-task:{}:{pid}", group.display()));
        std::fs::write(group.join(RESCTRL_TASKS), format!("{pid}\n"))
    }

    fn read_tasks(&self, group: &std::path::Path) -> std::io::Result<String> {
        std::fs::read_to_string(group.join(RESCTRL_TASKS))
    }

    fn remove_monitoring_group(&self, path: &std::path::Path) -> std::io::Result<()> {
        self.record(format!("remove-monitor:{}", path.display()));
        match std::fs::remove_file(path.join(RESCTRL_TASKS)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        std::fs::remove_dir(path)
    }

    fn remove_control_group(&self, path: &std::path::Path) -> std::io::Result<()> {
        self.record(format!("remove-control:{}", path.display()));
        for file in [RESCTRL_TASKS, RESCTRL_SCHEMATA] {
            match std::fs::remove_file(path.join(file)) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        match std::fs::remove_dir(path.join(RESCTRL_MON_GROUPS)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        std::fs::remove_dir(path)
    }
}

pub(super) struct Fixture {
    _temporary: TempDir,
    pub(super) root: std::path::PathBuf,
    pub(super) filesystem: FixtureFilesystem,
}

impl Fixture {
    pub(super) fn new() -> Self {
        let temporary = tempfile::tempdir().expect("temporary resctrl fixture");
        let root = temporary.path().join("resctrl");
        std::fs::create_dir(&root).expect("resctrl root");
        FixtureFilesystem::materialize_control(&root).expect("root control files");
        Self {
            _temporary: temporary,
            root,
            filesystem: FixtureFilesystem::default(),
        }
    }

    pub(super) fn preconfigured(&self, name: &str, schemata: &str) -> std::path::PathBuf {
        let path = self.root.join(name);
        std::fs::create_dir(&path).expect("preconfigured CLOS");
        FixtureFilesystem::materialize_control(&path).expect("preconfigured control files");
        std::fs::write(path.join(RESCTRL_SCHEMATA), schemata).expect("preconfigured schemata");
        path
    }
}
