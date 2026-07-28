use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command};

use super::pidfd::{PidFd, SignalOutcome};
use super::process_group::ProcessGroupLease;

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn reaper_lease_prevents_a_concurrent_numeric_group_signal() {
    let directory = tempfile::tempdir().expect("create process-group lease directory");
    let snapshot = directory.path().join("process.json");
    let signaler = ProcessGroupLease::open_for_snapshot_sync(&snapshot)
        .expect("open signal-side process-group lease");
    let reaper = ProcessGroupLease::open_for_snapshot_sync(&snapshot)
        .expect("open reaper-side process-group lease");

    let mut child = ChildGuard(
        Command::new("/bin/sleep")
            .arg("30")
            .process_group(0)
            .spawn()
            .expect("spawn process-group leader"),
    );
    let pid = i32::try_from(child.0.id()).expect("child PID fits process model");
    let pidfd = PidFd::open(pid).expect("open child pidfd");

    let reaping = reaper.lock_for_reap().expect("lock lease for reaping");
    assert_eq!(
        signaler
            .signal(&pidfd, libc::SIGKILL)
            .expect("busy signal lease must resolve as exited"),
        SignalOutcome::Exited
    );
    assert!(
        child
            .0
            .try_wait()
            .expect("inspect unsignaled child")
            .is_none(),
        "busy lease must prevent numeric process-group signaling"
    );
    reaping.unlock().expect("release reaper lease");

    assert_eq!(
        signaler
            .signal(&pidfd, libc::SIGKILL)
            .expect("signal process group after reaper release"),
        SignalOutcome::Delivered
    );
    assert_eq!(
        child.0.wait().expect("reap process-group leader").signal(),
        Some(libc::SIGKILL)
    );
}

#[test]
fn process_group_lease_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ProcessGroupLease>();
}
