use std::path::Path;

use a3s_oci_sdk::{Error, ErrorCode, Result, RuntimeArtifact};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt as _;
use tokio::sync::OnceCell;

static CURRENT_ARTIFACT: OnceCell<RuntimeArtifact> = OnceCell::const_new();

pub(super) async fn current() -> Result<RuntimeArtifact> {
    CURRENT_ARTIFACT.get_or_try_init(load).await.cloned()
}

async fn load() -> Result<RuntimeArtifact> {
    let executable = std::env::current_exe().map_err(|error| {
        artifact_error(format!(
            "failed to resolve the current runtime executable: {error}"
        ))
    })?;
    let digest = digest_file(&executable).await?;
    RuntimeArtifact::new(
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        digest,
        option_env!("A3S_OCI_GIT_REVISION").map(str::to_string),
    )
    .map_err(|error| {
        artifact_error(format!(
            "current runtime executable identity is invalid: {}",
            error.message
        ))
    })
}

async fn digest_file(path: &Path) -> Result<String> {
    let mut file = tokio::fs::File::open(path).await.map_err(|error| {
        artifact_error(format!(
            "failed to open current runtime executable {}: {error}",
            path.display()
        ))
    })?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).await.map_err(|error| {
            artifact_error(format!(
                "failed to read current runtime executable {}: {error}",
                path.display()
            ))
        })?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("sha256:{:x}", digest.finalize()))
}

fn artifact_error(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::Unavailable, message)
        .for_operation("features")
        .retryable(true)
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    #[tokio::test]
    async fn catalog_identity_matches_the_exact_host_test_executable() {
        let artifact = super::current().await.expect("runtime artifact identity");
        let executable = std::env::current_exe().expect("current test executable");
        let bytes = tokio::fs::read(executable)
            .await
            .expect("read current test executable");

        assert_eq!(artifact.name(), env!("CARGO_PKG_NAME"));
        assert_eq!(artifact.version(), env!("CARGO_PKG_VERSION"));
        assert_eq!(
            artifact.digest(),
            format!("sha256:{:x}", Sha256::digest(bytes))
        );
    }
}
