use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::{HookPhase, HookPlan, HookSet};

const OWNER_DEATH_CHILD_ENV: &str = "A3S_OCI_TEST_HOOK_OWNER_DEATH_CHILD";
const OWNER_DEATH_CHILD_TEST: &str = "executor::hook::owner_death_tests::hook_owner_death_child";
const OWNER_DEATH_LEADER_ENV: &str = "A3S_OCI_TEST_HOOK_OWNER_DEATH_LEADER";
const OWNER_DEATH_DESCENDANT_ENV: &str = "A3S_OCI_TEST_HOOK_OWNER_DEATH_DESCENDANT";

#[test]
fn hook_owner_death_child() {
    if std::env::var_os(OWNER_DEATH_CHILD_ENV).is_none() {
        return;
    }

    let leader = std::env::var(OWNER_DEATH_LEADER_ENV).expect("Hook leader evidence path");
    let descendant =
        std::env::var(OWNER_DEATH_DESCENDANT_ENV).expect("Hook descendant evidence path");
    let hooks = HookSet {
        prestart: vec![HookPlan {
            path: PathBuf::from("/bin/sh"),
            args: Some(vec![
                "a3s-hook".to_string(),
                "-c".to_string(),
                "set -eu; (trap '' HUP TERM; exec /bin/sleep 30) & child=$!; \
                 printf '%s\\n' \"$$\" > \"$LEADER\"; \
                 printf '%s\\n' \"$child\" > \"$DESCENDANT\"; \
                 exec /bin/sleep 30"
                    .to_string(),
            ]),
            environment: Some(vec![
                ("LEADER".to_string(), leader),
                ("DESCENDANT".to_string(), descendant),
            ]),
            timeout: Some(Duration::from_secs(20)),
        }],
        ..HookSet::default()
    };
    let _ = hooks.run_sync(HookPhase::Prestart, b"{}");
}

#[test]
fn owner_death_terminates_the_complete_hook_process_group() {
    let directory = tempfile::tempdir().expect("temporary Hook owner-death directory");
    let leader_path = directory.path().join("leader");
    let descendant_path = directory.path().join("descendant");
    let mut owner = Command::new(std::env::current_exe().expect("resolve test executable"))
        .args(["--exact", OWNER_DEATH_CHILD_TEST, "--nocapture"])
        .env(OWNER_DEATH_CHILD_ENV, "1")
        .env(OWNER_DEATH_LEADER_ENV, &leader_path)
        .env(OWNER_DEATH_DESCENDANT_ENV, &descendant_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("launch Hook owner-death child");

    let leader = wait_for_pid_evidence(&leader_path).unwrap_or_else(|error| {
        let _ = owner.kill();
        let _ = owner.wait();
        panic!("Hook leader startup failed: {error}");
    });
    let descendant = wait_for_pid_evidence(&descendant_path).unwrap_or_else(|error| {
        let _ = owner.kill();
        let _ = owner.wait();
        terminate_process_group(leader);
        panic!("Hook descendant startup failed: {error}");
    });

    let owner_pid = i32::try_from(owner.id()).expect("owner PID fits Linux pid_t");
    // SAFETY: owner identifies the exact retained test child.
    assert_eq!(unsafe { libc::kill(owner_pid, libc::SIGKILL) }, 0);
    owner.wait().expect("reap killed Hook owner");
    let terminated = wait_for_process_exit([leader, descendant], Duration::from_secs(2));
    if !terminated {
        terminate_process_group(leader);
        let _ = wait_for_process_exit([leader, descendant], Duration::from_secs(2));
    }
    assert!(
        terminated,
        "Hook process group survived owner death: leader={leader}, descendant={descendant}"
    );
}

fn wait_for_pid_evidence(path: &Path) -> std::io::Result<i32> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match std::fs::read_to_string(path) {
            Ok(value) => {
                let pid = value.trim().parse::<i32>().map_err(std::io::Error::other)?;
                return (pid > 0)
                    .then_some(pid)
                    .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData));
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}

fn wait_for_process_exit(processes: [i32; 2], timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if processes.iter().all(|pid| !process_is_live(*pid)) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn process_is_live(pid: i32) -> bool {
    // SAFETY: signal zero performs a read-only existence/permission probe.
    (unsafe { libc::kill(pid, 0) == 0 })
        || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn terminate_process_group(leader: i32) {
    // SAFETY: `leader` was published by the isolated Hook and is its exact
    // private process-group identifier.
    unsafe {
        libc::kill(-leader, libc::SIGKILL);
    }
}
