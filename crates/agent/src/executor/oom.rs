use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};

use a3s_oci_sdk::{Error, ErrorCode, Result};

const OOM_SCORE_ADJ_MIN: i32 = -1000;
const OOM_SCORE_ADJ_MAX: i32 = 1000;
const OOM_SCORE_ADJ_PATH: &str = "self/oom_score_adj";
const MAX_OOM_SCORE_ADJ_BYTES: u64 = 32;

/// Apply the optional OCI OOM adjustment through procfs retained before
/// namespace and root changes. An omitted value deliberately performs no
/// open, read, or write so the inherited kernel value remains unchanged.
pub(super) fn apply(host_proc: &File, requested: Option<i32>) -> Result<()> {
    let Some(requested) = requested else {
        return Ok(());
    };
    if !(OOM_SCORE_ADJ_MIN..=OOM_SCORE_ADJ_MAX).contains(&requested) {
        return Err(oom_error(
            ErrorCode::InvalidArgument,
            format!(
                "process.oomScoreAdj {requested} is outside the Linux kernel range \
                 {OOM_SCORE_ADJ_MIN}..={OOM_SCORE_ADJ_MAX}"
            ),
        ));
    }

    let mut destination = open_score_file(host_proc, libc::O_WRONLY, "write")?;
    destination
        .write_all(requested.to_string().as_bytes())
        .map_err(|source| {
            oom_error(
                error_code_for_io(&source),
                format!("failed to write process.oomScoreAdj {requested}: {source}"),
            )
        })?;
    drop(destination);

    let source = open_score_file(host_proc, libc::O_RDONLY, "verify")?;
    let mut bytes = Vec::new();
    source
        .take(MAX_OOM_SCORE_ADJ_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| {
            oom_error(
                error_code_for_io(&source),
                format!("failed to read back process.oomScoreAdj {requested}: {source}"),
            )
        })?;
    if bytes.len() as u64 > MAX_OOM_SCORE_ADJ_BYTES {
        return Err(oom_error(
            ErrorCode::ResourceExhausted,
            format!("process oom_score_adj read-back exceeds {MAX_OOM_SCORE_ADJ_BYTES} bytes"),
        ));
    }
    let encoded = std::str::from_utf8(&bytes).map_err(|source| {
        oom_error(
            ErrorCode::FailedPrecondition,
            format!("process oom_score_adj read-back is not UTF-8: {source}"),
        )
    })?;
    let actual = encoded.trim().parse::<i32>().map_err(|source| {
        oom_error(
            ErrorCode::FailedPrecondition,
            format!("process oom_score_adj read-back is not an integer: {source}"),
        )
    })?;
    if actual != requested {
        return Err(oom_error(
            ErrorCode::FailedPrecondition,
            format!(
                "process.oomScoreAdj read-back mismatch: requested {requested}, observed {actual}"
            ),
        ));
    }
    Ok(())
}

fn open_score_file(host_proc: &File, access: libc::c_int, purpose: &str) -> Result<File> {
    let path = CString::new(OOM_SCORE_ADJ_PATH).map_err(|source| {
        oom_error(
            ErrorCode::Internal,
            format!("retained oom_score_adj path is invalid: {source}"),
        )
    })?;
    // SAFETY: `host_proc` is a live retained directory descriptor, `path` is
    // NUL-terminated, and a successful fresh descriptor is transferred once
    // to `File`. `O_NOFOLLOW` protects the final procfs node while allowing
    // procfs's intermediate magic `self` link to resolve for this process.
    let descriptor = unsafe {
        libc::openat(
            host_proc.as_raw_fd(),
            path.as_ptr(),
            access | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        let source = io::Error::last_os_error();
        return Err(oom_error(
            error_code_for_io(&source),
            format!(
                "failed to open retained procfs {OOM_SCORE_ADJ_PATH} to {purpose} \
                 process.oomScoreAdj: {source}"
            ),
        ));
    }
    // SAFETY: `openat` returned a fresh owned descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn error_code_for_io(source: &io::Error) -> ErrorCode {
    match source.raw_os_error() {
        Some(libc::EACCES | libc::EPERM) => ErrorCode::PermissionDenied,
        Some(libc::ENOENT | libc::ENOTDIR) => ErrorCode::FailedPrecondition,
        Some(libc::EINVAL) => ErrorCode::InvalidArgument,
        _ => ErrorCode::Internal,
    }
}

fn oom_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("apply-process-oom-score-adj")
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io;
    use std::process::Command;

    use a3s_oci_sdk::ErrorCode;
    use tempfile::tempdir;

    use super::{apply, error_code_for_io};

    const CHILD_PROBE: &str = "A3S_OCI_OOM_SCORE_ADJ_CHILD_PROBE";
    const APPLY_TEST: &str = "executor::oom::tests::applies_exact_value_in_an_isolated_process";

    fn fake_proc(initial: &str) -> (tempfile::TempDir, File) {
        let temporary = tempdir().expect("temporary procfs");
        let process = temporary.path().join("self");
        std::fs::create_dir(&process).expect("fake self directory");
        std::fs::write(process.join("oom_score_adj"), initial).expect("fake OOM score");
        let retained = File::open(temporary.path()).expect("retain fake procfs");
        (temporary, retained)
    }

    #[test]
    fn applies_and_reads_back_exact_value_through_a_retained_directory() {
        let (temporary, retained) = fake_proc("0\n");
        apply(&retained, Some(250)).expect("apply fake OOM score");
        assert_eq!(
            std::fs::read_to_string(temporary.path().join("self/oom_score_adj"))
                .expect("read fake OOM score"),
            "250"
        );
    }

    #[test]
    fn omitted_value_does_not_open_or_modify_procfs() {
        let temporary = tempdir().expect("empty fake procfs");
        let retained = File::open(temporary.path()).expect("retain empty fake procfs");
        apply(&retained, None).expect("omit OOM score without procfs access");
        assert!(temporary
            .path()
            .read_dir()
            .expect("read fake procfs")
            .next()
            .is_none());
    }

    #[test]
    fn rejects_out_of_range_and_mismatched_kernel_values() {
        let (_temporary, retained) = fake_proc("0\n");
        let error = apply(&retained, Some(1001)).expect_err("out-of-range score must fail");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert!(error.message.contains("outside the Linux kernel range"));

        let (_temporary, retained) = fake_proc("9999");
        let error = apply(&retained, Some(1)).expect_err("mismatched read-back must fail");
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert!(
            error.message.contains("read-back mismatch"),
            "unexpected mismatch error: {error:?}"
        );
    }

    #[test]
    fn reports_format_open_and_permission_failures_with_context() {
        let (_temporary, retained) = fake_proc("bad");
        let error = apply(&retained, Some(1)).expect_err("malformed read-back must fail");
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert!(
            error.message.contains("read-back is not an integer"),
            "unexpected format error: {error:?}"
        );

        let temporary = tempdir().expect("temporary procfs");
        std::fs::create_dir_all(temporary.path().join("self/oom_score_adj"))
            .expect("directory in place of OOM score");
        let retained = File::open(temporary.path()).expect("retain fake procfs");
        let error = apply(&retained, Some(1)).expect_err("non-file score must fail");
        assert!(error.message.contains("process.oomScoreAdj"));

        assert_eq!(
            error_code_for_io(&io::Error::from_raw_os_error(libc::EACCES)),
            ErrorCode::PermissionDenied
        );
        assert_eq!(
            error_code_for_io(&io::Error::from_raw_os_error(libc::EPERM)),
            ErrorCode::PermissionDenied
        );
    }

    #[test]
    fn applies_exact_value_in_an_isolated_process() {
        if std::env::var_os(CHILD_PROBE).is_some() {
            let before = std::fs::read_to_string("/proc/self/oom_score_adj")
                .expect("read initial OOM score")
                .trim()
                .parse::<i32>()
                .expect("parse initial OOM score");
            let requested = (before + 1).min(1000);
            let retained = File::open("/proc").expect("retain real procfs");
            apply(&retained, Some(requested)).expect("apply real OOM score");
            let actual = std::fs::read_to_string("/proc/self/oom_score_adj")
                .expect("read applied OOM score")
                .trim()
                .parse::<i32>()
                .expect("parse applied OOM score");
            assert_eq!(actual, requested);
            return;
        }

        let output = Command::new(std::env::current_exe().expect("resolve test executable"))
            .args(["--exact", APPLY_TEST, "--nocapture"])
            .env(CHILD_PROBE, "1")
            .output()
            .expect("run isolated OOM score probe");
        assert!(
            output.status.success(),
            "isolated OOM score probe failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
