use std::io;

use a3s_oci_sdk::{Error, ErrorCode, Result};

pub(super) fn apply(enabled: bool) -> Result<()> {
    if !enabled {
        return Ok(());
    }

    // SAFETY: `PR_SET_NO_NEW_PRIVS` consumes a boolean integer and zero
    // padding arguments for the calling thread.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(last_os_error("enable no_new_privileges"));
    }
    let actual = read_current()?;
    if actual == 1 {
        Ok(())
    } else {
        Err(no_new_privileges_error(
            ErrorCode::FailedPrecondition,
            format!("kernel reported no_new_privileges={actual} after enforcement"),
        ))
    }
}

fn read_current() -> Result<libc::c_int> {
    // SAFETY: `PR_GET_NO_NEW_PRIVS` reads the calling thread's flag and
    // requires zero padding arguments.
    let value = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    if value < 0 {
        Err(last_os_error("verify no_new_privileges"))
    } else {
        Ok(value)
    }
}

fn last_os_error(operation: &str) -> Error {
    no_new_privileges_error(
        ErrorCode::PermissionDenied,
        format!("failed to {operation}: {}", io::Error::last_os_error()),
    )
}

fn no_new_privileges_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("apply-no-new-privileges")
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::{apply, read_current};

    const CHILD_ENV: &str = "A3S_OCI_NO_NEW_PRIVILEGES_TEST_CHILD";

    #[test]
    fn applies_and_reads_back_in_isolated_process() {
        if std::env::var_os(CHILD_ENV).is_some() {
            apply(true).expect("apply no_new_privileges in child");
            assert_eq!(read_current().expect("read no_new_privileges in child"), 1);
            return;
        }

        let output = Command::new(std::env::current_exe().expect("current test executable"))
            .arg("applies_and_reads_back_in_isolated_process")
            .arg("--nocapture")
            .env(CHILD_ENV, "1")
            .output()
            .expect("spawn isolated no_new_privileges test child");
        assert!(
            output.status.success(),
            "isolated no_new_privileges child failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn disabled_request_does_not_change_the_current_process() {
        let before = read_current().expect("read initial no_new_privileges");
        apply(false).expect("disabled request must be a no-op");
        assert_eq!(
            read_current().expect("read final no_new_privileges"),
            before
        );
    }
}
