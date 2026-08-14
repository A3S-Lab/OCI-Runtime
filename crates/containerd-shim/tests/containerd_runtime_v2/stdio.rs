use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncWriteExt;

use super::support::*;

pub(crate) async fn qualify_ctr_stdio(
    config: &QualificationConfig,
    prefix: &str,
) -> TestResult<()> {
    qualify_stdin(config, prefix).await?;
    qualify_stdout_stderr(config, prefix).await
}

async fn qualify_stdin(config: &QualificationConfig, prefix: &str) -> TestResult<()> {
    for (name, bytes, delay) in [
        ("empty", Vec::new(), Duration::ZERO),
        ("delayed", b"abc".to_vec(), Duration::from_secs(1)),
        ("small", vec![0x5a; 262_161], Duration::ZERO),
        ("medium", vec![0xa5; 1_048_593], Duration::ZERO),
        ("large", vec![0x3c; 4_194_321], Duration::ZERO),
    ] {
        let id = format!("{prefix}-stdin-{name}");
        let mut command = ctr_command(config);
        command
            .args([
                "run",
                "--rm",
                "--runtime",
                &config.runtime,
                &config.image,
                &id,
                "/bin/sh",
                "-c",
                "wc -c",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(|error| {
            qualification_error(format!("start ctr stdin case {name}: {error}"))
        })?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| qualification_error(format!("ctr stdin case {name} has no pipe")))?;
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        stdin.write_all(&bytes).await.map_err(|error| {
            qualification_error(format!("write ctr stdin case {name}: {error}"))
        })?;
        stdin.shutdown().await.map_err(|error| {
            qualification_error(format!("close ctr stdin case {name}: {error}"))
        })?;
        drop(stdin);
        let output = tokio::time::timeout(COMMAND_TIMEOUT, child.wait_with_output())
            .await
            .map_err(|_| qualification_error(format!("ctr stdin case {name} timed out")))?
            .map_err(|error| {
                qualification_error(format!("wait for ctr stdin case {name}: {error}"))
            })?;
        require_success(&format!("ctr stdin case {name}"), &output)?;
        let actual = String::from_utf8(output.stdout)
            .map_err(|error| qualification_error(format!("decode {name} count: {error}")))?;
        if actual.trim() != bytes.len().to_string() {
            return Err(qualification_error(format!(
                "ctr stdin case {name} delivered {}, expected {} bytes",
                actual.trim(),
                bytes.len()
            ))
            .into());
        }
    }
    Ok(())
}

async fn qualify_stdout_stderr(config: &QualificationConfig, prefix: &str) -> TestResult<()> {
    let id = format!("{prefix}-stdio-output");
    let mut command = ctr_command(config);
    command.args([
        "run",
        "--rm",
        "--runtime",
        &config.runtime,
        &config.image,
        &id,
        "/bin/sh",
        "-c",
        "printf 'stdout-marker\\n'; printf 'stderr-marker\\n' >&2",
    ]);
    let output = tokio::time::timeout(COMMAND_TIMEOUT, command.output())
        .await
        .map_err(|_| qualification_error("ctr stdout/stderr case timed out"))?
        .map_err(|error| qualification_error(format!("run ctr stdout/stderr case: {error}")))?;
    require_success("ctr stdout/stderr case", &output)?;
    if output.stdout != b"stdout-marker\n" {
        return Err(qualification_error(format!(
            "ctr stdout bytes were {:?}, expected one stdout marker",
            String::from_utf8_lossy(&output.stdout)
        ))
        .into());
    }
    if output.stderr != b"stderr-marker\n" {
        return Err(qualification_error(format!(
            "ctr stderr bytes were {:?}, expected one stderr marker",
            String::from_utf8_lossy(&output.stderr)
        ))
        .into());
    }
    Ok(())
}
