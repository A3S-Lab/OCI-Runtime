//! Host-visible console normalization for the Windows libkrun bootstrap.

use std::path::Path;

const MAX_LOG_BYTES: u64 = 64 * 1024;
const MAX_MERGED_CONSOLE_BYTES: usize = 1024 * 1024;
const EVIDENCE_PREFIX: &[u8] = b"A3S_OCI_AGENT_TRANSPORT_QUALIFICATION_EVIDENCE ";
const LOG_NAMES: &[&str] = &[
    "guest-init.stderr.log",
    "guest-init.stdout.log",
    "init-rust.log",
    "init.krun.log",
    "init.trace.log",
];

/// Merge the fixed init-wrapper logs into the configured host console.
///
/// Windows libkrun creates the configured console file, while `init.krun`
/// redirects the launched workload streams into bounded files below the
/// bootstrap root. Normalizing both sources here gives the host one stable
/// console artifact without trusting arbitrary guest paths.
pub(crate) fn merge(rootfs: &Path, console: &Path) -> Result<(), String> {
    let console_metadata = std::fs::symlink_metadata(console).map_err(|error| {
        format!(
            "failed to inspect Windows guest console {}: {error}",
            console.display()
        )
    })?;
    if !console_metadata.is_file() || console_metadata.file_type().is_symlink() {
        return Err(format!(
            "Windows guest console is not a regular file: {}",
            console.display()
        ));
    }
    if console_metadata.len() > MAX_MERGED_CONSOLE_BYTES as u64 {
        return Err(format!(
            "Windows guest console exceeds {MAX_MERGED_CONSOLE_BYTES} bytes: {}",
            console.display()
        ));
    }

    let mut merged = std::fs::read(console).map_err(|error| {
        format!(
            "failed to read Windows guest console {}: {error}",
            console.display()
        )
    })?;
    if merged
        .windows(EVIDENCE_PREFIX.len())
        .any(|window| window == EVIDENCE_PREFIX)
    {
        return Ok(());
    }
    let original_len = merged.len();

    for name in LOG_NAMES {
        let path = rootfs.join(name);
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(format!(
                "Windows bootstrap log is not a regular file: {}",
                path.display()
            ));
        }
        if metadata.len() > MAX_LOG_BYTES {
            return Err(format!(
                "Windows bootstrap log exceeds {MAX_LOG_BYTES} bytes: {}",
                path.display()
            ));
        }
        let content = std::fs::read(&path).map_err(|error| {
            format!(
                "failed to read Windows bootstrap log {}: {error}",
                path.display()
            )
        })?;
        if content.is_empty() {
            continue;
        }
        if !merged.is_empty() && !merged.ends_with(b"\n") {
            merged.push(b'\n');
        }
        merged.extend_from_slice(&content);
        if !merged.ends_with(b"\n") {
            merged.push(b'\n');
        }
        if merged.len() > MAX_MERGED_CONSOLE_BYTES {
            return Err(format!(
                "merged Windows guest console exceeds {MAX_MERGED_CONSOLE_BYTES} bytes: {}",
                console.display()
            ));
        }
    }

    if merged.len() != original_len {
        std::fs::write(console, merged).map_err(|error| {
            format!(
                "failed to merge Windows bootstrap logs into {}: {error}",
                console.display()
            )
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::merge;

    #[test]
    fn appends_fixed_bootstrap_logs_to_the_host_console() {
        let temporary = tempfile::tempdir().expect("temporary bootstrap root");
        let console = temporary.path().join("console.log");
        std::fs::write(&console, b"firmware\n").expect("write host console");
        std::fs::write(temporary.path().join("guest-init.stdout.log"), b"guest\n")
            .expect("write guest stdout");
        std::fs::write(temporary.path().join("init.trace.log"), b"trace")
            .expect("write init trace");

        merge(temporary.path(), &console).expect("merge bootstrap logs");

        assert_eq!(
            std::fs::read(&console).expect("read merged console"),
            b"firmware\nguest\ntrace\n"
        );
    }

    #[test]
    fn rejects_an_oversized_bootstrap_log_before_merging() {
        let temporary = tempfile::tempdir().expect("temporary bootstrap root");
        let console = temporary.path().join("console.log");
        std::fs::write(&console, b"firmware\n").expect("write host console");
        std::fs::write(
            temporary.path().join("guest-init.stderr.log"),
            vec![b'x'; 64 * 1024 + 1],
        )
        .expect("write oversized bootstrap log");

        let error = merge(temporary.path(), &console).expect_err("oversized log must fail");
        assert!(error.contains("exceeds 65536 bytes"), "{error}");
        assert_eq!(
            std::fs::read(&console).expect("read unchanged console"),
            b"firmware\n"
        );
    }
}
