use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use a3s_oci_sdk::OciBundle;
use serde_json::{json, Map, Value};
use tokio::io::AsyncReadExt;

use crate::RootfsMountEvidence;

const EVIDENCE_FILE: &str = "evidence";
const BIND_SOURCE_FILE: &str = "bind-source";
const BIND_SOURCE_CONTENTS: &[u8] = b"a3s-oci-bind-source-v1";
const MAX_EVIDENCE_BYTES: u64 = 1_024;
const EXPECTED_EVIDENCE: &[u8] = b"mount-target-created\n\
mount-file-target-created\n\
rootfs-propagation-shared\n\
readonly-path-enforced\n\
masked-file-empty-readonly\n\
masked-directory-empty-readonly\n\
masked-path-enforced\n\
recursive-mount-attributes-enforced\n\
readonly-rootfs-enforced\n";

pub(crate) struct RootfsEnforcementFixture {
    pub(crate) bundle: OciBundle,
    output_directory: PathBuf,
    target_directory: PathBuf,
}

impl RootfsEnforcementFixture {
    pub(crate) async fn prepare(base: &OciBundle, nonce: &str) -> Result<Self, String> {
        let component = safe_component(nonce)?;
        let output_name = format!(".a3s-oci-rootfs-output-{component}");
        let target_name = format!(".a3s-oci-rootfs-target-{component}");
        let output_directory = base.directory().join(&output_name);
        let target_directory = base.directory().join("rootfs").join(&target_name);
        ensure_absent(&output_directory, "rootfs evidence output").await?;
        ensure_absent(&target_directory, "rootfs mount target").await?;

        let bundle = build_bundle(base, &output_name, &target_name, component)?;
        tokio::fs::create_dir(&output_directory)
            .await
            .map_err(|error| {
                format!(
                    "failed to create rootfs evidence output {}: {error}",
                    output_directory.display()
                )
            })?;
        if let Err(error) = tokio::fs::write(
            output_directory.join(BIND_SOURCE_FILE),
            BIND_SOURCE_CONTENTS,
        )
        .await
        {
            let _ = tokio::fs::remove_dir_all(&output_directory).await;
            return Err(format!(
                "failed to create rootfs enforcement bind source: {error}"
            ));
        }
        Ok(Self {
            bundle,
            output_directory,
            target_directory,
        })
    }

    pub(crate) async fn targets_created(&self) -> Result<bool, String> {
        let output_target = self.target_directory.join("output");
        let tmpfs_target = self.target_directory.join("tmpfs/nested");
        let file_target = self.target_directory.join("bound-file");
        let recursive_source = self.target_directory.join("recursive/source");
        let recursive_target = self.target_directory.join("recursive/readonly");
        Ok(real_directory(&output_target).await?
            && real_directory(&tmpfs_target).await?
            && real_file(&file_target).await?
            && real_directory(&recursive_source).await?
            && real_directory(&recursive_target).await?)
    }

    pub(crate) async fn evidence_absent(&self) -> Result<bool, String> {
        path_absent(&self.output_directory.join(EVIDENCE_FILE)).await
    }

    pub(crate) async fn read_evidence(&self) -> Result<Vec<u8>, String> {
        let path = self.output_directory.join(EVIDENCE_FILE);
        let file = tokio::fs::File::open(&path).await.map_err(|error| {
            format!(
                "failed to open rootfs enforcement evidence {}: {error}",
                path.display()
            )
        })?;
        let metadata = file.metadata().await.map_err(|error| {
            format!(
                "failed to inspect rootfs enforcement evidence {}: {error}",
                path.display()
            )
        })?;
        if !metadata.is_file() || metadata.len() > MAX_EVIDENCE_BYTES {
            return Err(format!(
                "rootfs enforcement evidence must be a regular file no larger than \
                 {MAX_EVIDENCE_BYTES} bytes"
            ));
        }
        let mut evidence = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_EVIDENCE_BYTES + 1)
            .read_to_end(&mut evidence)
            .await
            .map_err(|error| {
                format!(
                    "failed to read rootfs enforcement evidence {}: {error}",
                    path.display()
                )
            })?;
        if evidence.len() as u64 > MAX_EVIDENCE_BYTES {
            return Err("rootfs enforcement evidence exceeded its bounded size".into());
        }
        Ok(evidence)
    }

    pub(crate) async fn collect_evidence(
        &self,
        report: &mut RootfsMountEvidence,
    ) -> Result<String, String> {
        let evidence = self.read_evidence().await?;
        let evidence_text = std::str::from_utf8(&evidence)
            .map_err(|error| format!("rootfs enforcement evidence is not UTF-8: {error}"))?;
        let lines = evidence_text.lines().collect::<Vec<_>>();
        report.rootfs_propagation_shared = lines.contains(&"rootfs-propagation-shared");
        report.readonly_path_enforced = lines.contains(&"readonly-path-enforced");
        report.masked_path_enforced = lines.contains(&"masked-path-enforced");
        report.recursive_mount_attributes_enforced =
            lines.contains(&"recursive-mount-attributes-enforced");
        report.readonly_rootfs_enforced = lines.contains(&"readonly-rootfs-enforced");
        report.exact_evidence = evidence == EXPECTED_EVIDENCE;
        Ok(evidence_text.to_string())
    }

    pub(crate) async fn cleanup(&self) -> Result<bool, String> {
        remove_tree(&self.output_directory, "rootfs evidence output").await?;
        remove_tree(&self.target_directory, "rootfs mount target").await?;
        Ok(path_absent(&self.output_directory).await?
            && path_absent(&self.target_directory).await?)
    }
}

fn build_bundle(
    base: &OciBundle,
    output_name: &str,
    target_name: &str,
    nonce: &str,
) -> Result<OciBundle, String> {
    let mut config: Value = serde_json::from_str(base.config_json())
        .map_err(|error| format!("failed to decode rootfs enforcement base config: {error}"))?;
    let root = object_mut(&mut config, "config")?;
    let root_config = root
        .get_mut("root")
        .ok_or_else(|| "rootfs enforcement config.root is required".to_string())?;
    object_mut(root_config, "root")?.insert("readonly".into(), Value::Bool(true));

    let target_root = format!("/{target_name}");
    let output_target = format!("{target_root}/output");
    let tmpfs_target = format!("{target_root}/tmpfs/nested");
    let file_target = format!("{target_root}/bound-file");
    let file_source = format!("{output_name}/{BIND_SOURCE_FILE}");
    let recursive_source = format!("{target_root}/recursive/source");
    let recursive_source_child = format!("{recursive_source}/child");
    let recursive_target = format!("{target_root}/recursive/readonly");
    let recursive_source_in_bundle = format!("rootfs{recursive_source}");
    root.insert(
        "mounts".into(),
        json!([
            {
                "destination": "/proc",
                "type": "proc",
                "source": "proc",
                "options": ["nosuid", "noexec", "nodev"]
            },
            {
                "destination": output_target,
                "type": "none",
                "source": output_name,
                "options": ["rbind", "rw", "nosuid", "nodev"]
            },
            {
                "destination": tmpfs_target,
                "type": "tmpfs",
                "source": "tmpfs",
                "options": ["nosuid", "noexec", "nodev", "mode=0700", "size=64k"]
            },
            {
                "destination": file_target,
                "type": "none",
                "source": file_source,
                "options": ["bind", "ro", "nosuid", "nodev"]
            },
            {
                "destination": recursive_source,
                "type": "tmpfs",
                "source": "tmpfs",
                "options": ["rw", "nosuid", "nodev", "mode=0700", "size=64k"]
            },
            {
                "destination": recursive_source_child,
                "type": "tmpfs",
                "source": "tmpfs",
                "options": ["rw", "nosuid", "nodev", "mode=0700", "size=64k"]
            },
            {
                "destination": recursive_target,
                "type": "none",
                "source": recursive_source_in_bundle,
                "options": [
                    "rbind",
                    "rro",
                    "rnosuid",
                    "rnodev",
                    "rnoexec",
                    "rnoatime",
                    "rnodiratime",
                    "rnosymfollow"
                ]
            }
        ]),
    );

    let linux = root
        .get_mut("linux")
        .ok_or_else(|| "rootfs enforcement config.linux is required".to_string())?;
    let linux = object_mut(linux, "linux")?;
    linux.insert("rootfsPropagation".into(), Value::String("shared".into()));
    linux.insert("maskedPaths".into(), json!(["/proc/meminfo", "/proc/irq"]));
    linux.insert("readonlyPaths".into(), json!(["/proc/sys"]));

    let evidence_path = format!("{target_root}/output/{EVIDENCE_FILE}");
    let write_probe = format!("/.a3s-oci-readonly-probe-{nonce}");
    let command = enforcement_command(
        &evidence_path,
        &tmpfs_target,
        &file_target,
        &recursive_source,
        &recursive_target,
        &write_probe,
    );
    *process_command_mut(root)? = command;

    let config = serde_json::to_string(&config)
        .map_err(|error| format!("failed to encode rootfs enforcement config: {error}"))?;
    OciBundle::from_json(base.directory().to_path_buf(), config)
        .map_err(|error| format!("failed to validate rootfs enforcement bundle: {error}"))
}

fn enforcement_command(
    evidence: &str,
    tmpfs_target: &str,
    file_target: &str,
    recursive_source: &str,
    recursive_target: &str,
    write_probe: &str,
) -> String {
    let recursive_source_child = format!("{recursive_source}/child");
    let recursive_target_child = format!("{recursive_target}/child");
    format!(
        "set -eu; \
         evidence='{evidence}'; \
         : > \"$evidence\"; \
         test -d '{tmpfs_target}'; \
         /bin/busybox awk '$5 == \"{tmpfs_target}\" {{ ok = 1 }} END {{ exit !ok }}' \
           /proc/self/mountinfo; \
         printf 'mount-target-created\\n' >> \"$evidence\"; \
         test -f '{file_target}'; \
         test \"$(/bin/busybox cat '{file_target}')\" = 'a3s-oci-bind-source-v1'; \
         /bin/busybox awk '$5 == \"{file_target}\" {{ ok = 1 }} END {{ exit !ok }}' \
           /proc/self/mountinfo; \
         printf 'mount-file-target-created\\n' >> \"$evidence\"; \
         /bin/busybox awk '$5 == \"/\" {{ for (i = 7; i <= NF && $i != \"-\"; i++) \
           if ($i ~ /^shared:/) ok = 1 }} END {{ exit !ok }}' /proc/self/mountinfo; \
         printf 'rootfs-propagation-shared\\n' >> \"$evidence\"; \
         /bin/busybox awk '$5 == \"/proc/sys\" && $6 ~ /(^|,)ro(,|$)/ {{ ok = 1 }} \
           END {{ exit !ok }}' /proc/self/mountinfo; \
         printf 'readonly-path-enforced\\n' >> \"$evidence\"; \
         /bin/busybox awk '$5 == \"/proc/meminfo\" && $6 ~ /(^|,)ro(,|$)/ {{ ok = 1 }} \
           END {{ exit !ok }}' /proc/self/mountinfo; \
         test -f /proc/meminfo; test ! -s /proc/meminfo; \
         test -z \"$(/bin/busybox cat /proc/meminfo)\"; \
         printf 'masked-file-empty-readonly\\n' >> \"$evidence\"; \
         /bin/busybox awk '$5 == \"/proc/irq\" && $6 ~ /(^|,)ro(,|$)/ {{ ok = 1 }} \
           END {{ exit !ok }}' /proc/self/mountinfo; \
         test -d /proc/irq; test -z \"$(/bin/busybox ls -A /proc/irq)\"; \
         printf 'masked-directory-empty-readonly\\n' >> \"$evidence\"; \
         printf 'masked-path-enforced\\n' >> \"$evidence\"; \
         for path in '{recursive_target}' '{recursive_target_child}'; do \
           /bin/busybox awk -v path=\"$path\" '$5 == path && \
             $6 ~ /(^|,)ro(,|$)/ && $6 ~ /(^|,)nosuid(,|$)/ && \
             $6 ~ /(^|,)nodev(,|$)/ && $6 ~ /(^|,)noexec(,|$)/ && \
             $6 ~ /(^|,)noatime(,|$)/ && $6 ~ /(^|,)nodiratime(,|$)/ && \
             $6 ~ /(^|,)nosymfollow(,|$)/ {{ ok = 1 }} END {{ exit !ok }}' \
             /proc/self/mountinfo; \
         done; \
         for path in '{recursive_source}' '{recursive_source_child}'; do \
           /bin/busybox touch \"$path/write-probe\"; \
           /bin/busybox rm \"$path/write-probe\"; \
           printf '#!/bin/sh\\nexit 0\\n' > \"$path/exec-probe\"; \
           /bin/busybox chmod 0700 \"$path/exec-probe\"; \
           \"$path/exec-probe\"; \
           printf 'symlink-source\\n' > \"$path/symlink-source\"; \
           /bin/busybox ln -s symlink-source \"$path/symlink-probe\"; \
         done; \
         for path in '{recursive_target}' '{recursive_target_child}'; do \
           if /bin/busybox touch \"$path/write-probe\" 2>/dev/null; then exit 42; fi; \
           if \"$path/exec-probe\" 2>/dev/null; then exit 43; fi; \
           if /bin/busybox cat \"$path/symlink-probe\" >/dev/null 2>&1; then exit 44; fi; \
         done; \
         printf 'recursive-mount-attributes-enforced\\n' >> \"$evidence\"; \
         /bin/busybox awk '$5 == \"/\" && $6 ~ /(^|,)ro(,|$)/ {{ ok = 1 }} \
           END {{ exit !ok }}' /proc/self/mountinfo; \
         if /bin/busybox touch '{write_probe}' 2>/dev/null; then \
           /bin/busybox rm -f '{write_probe}'; exit 41; \
         fi; \
         printf 'readonly-rootfs-enforced\\n' >> \"$evidence\""
    )
}

fn process_command_mut(root: &mut Map<String, Value>) -> Result<&mut String, String> {
    let command = root
        .get_mut("process")
        .and_then(Value::as_object_mut)
        .and_then(|process| process.get_mut("args"))
        .and_then(Value::as_array_mut)
        .and_then(|args| args.get_mut(2))
        .ok_or_else(|| {
            "rootfs enforcement fixture requires process.args[2] to be a shell command".to_string()
        })?;
    command.as_str().ok_or_else(|| {
        "rootfs enforcement fixture requires process.args[2] to be a string".to_string()
    })?;
    match command {
        Value::String(command) => Ok(command),
        _ => Err("rootfs enforcement process command is not a string".into()),
    }
}

fn object_mut<'a>(value: &'a mut Value, field: &str) -> Result<&'a mut Map<String, Value>, String> {
    value
        .as_object_mut()
        .ok_or_else(|| format!("rootfs enforcement {field} must be an object"))
}

fn safe_component(value: &str) -> Result<&str, String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        Err(
            "rootfs enforcement nonce must contain only bounded ASCII letters, digits, or hyphens"
                .into(),
        )
    } else {
        Ok(value)
    }
}

async fn ensure_absent(path: &Path, description: &str) -> Result<(), String> {
    if path_absent(path).await? {
        Ok(())
    } else {
        Err(format!(
            "refusing to replace an existing {description}: {}",
            path.display()
        ))
    }
}

async fn path_absent(path: &Path) -> Result<bool, String> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(true),
        Err(error) => Err(format!("failed to inspect {}: {error}", path.display())),
    }
}

async fn real_directory(path: &Path) -> Result<bool, String> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) => Ok(metadata.is_dir() && !metadata.file_type().is_symlink()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("failed to inspect {}: {error}", path.display())),
    }
}

async fn real_file(path: &Path) -> Result<bool, String> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) => Ok(metadata.is_file() && !metadata.file_type().is_symlink()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("failed to inspect {}: {error}", path.display())),
    }
}

async fn remove_tree(path: &Path, description: &str) -> Result<(), String> {
    match tokio::fs::remove_dir_all(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "failed to remove {description} {}: {error}",
            path.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use a3s_oci_sdk::OciBundle;
    use serde_json::Value;
    use tempfile::tempdir;

    use super::RootfsEnforcementFixture;

    const CONFIG: &str = include_str!("../../../fixtures/utility-vm/config.json");

    #[tokio::test]
    async fn derives_and_cleans_a_complete_rootfs_enforcement_fixture() {
        let temporary = tempdir().expect("temporary rootfs fixture");
        let bundle_directory = temporary.path().join("bundle");
        std::fs::create_dir_all(bundle_directory.join("rootfs")).expect("fixture rootfs");
        let base = OciBundle::from_json(bundle_directory, CONFIG).expect("qualified base bundle");

        let fixture = RootfsEnforcementFixture::prepare(&base, "fixture-123")
            .await
            .expect("rootfs enforcement fixture");
        let config: Value =
            serde_json::from_str(fixture.bundle.config_json()).expect("enforcement JSON");

        assert_eq!(config["root"]["readonly"], Value::Bool(true));
        assert_eq!(
            config["linux"]["rootfsPropagation"],
            Value::String("shared".into())
        );
        assert_eq!(
            config["linux"]["maskedPaths"],
            serde_json::json!(["/proc/meminfo", "/proc/irq"])
        );
        assert_eq!(
            config["linux"]["readonlyPaths"],
            serde_json::json!(["/proc/sys"])
        );
        assert_eq!(
            config["mounts"][1]["source"],
            Value::String(".a3s-oci-rootfs-output-fixture-123".into())
        );
        assert_eq!(
            config["mounts"][3]["source"],
            Value::String(".a3s-oci-rootfs-output-fixture-123/bind-source".into())
        );
        let recursive_mount = config["mounts"]
            .as_array()
            .expect("mount array")
            .iter()
            .find(|mount| {
                mount["destination"]
                    .as_str()
                    .is_some_and(|path| path.ends_with("/recursive/readonly"))
            })
            .expect("recursive-attribute mount");
        assert_eq!(
            recursive_mount["options"],
            serde_json::json!([
                "rbind",
                "rro",
                "rnosuid",
                "rnodev",
                "rnoexec",
                "rnoatime",
                "rnodiratime",
                "rnosymfollow"
            ])
        );
        let command = config["process"]["args"][2]
            .as_str()
            .expect("enforcement command");
        for assertion in [
            "mount-target-created",
            "mount-file-target-created",
            "rootfs-propagation-shared",
            "readonly-path-enforced",
            "masked-directory-empty-readonly",
            "masked-path-enforced",
            "recursive-mount-attributes-enforced",
            "readonly-rootfs-enforced",
        ] {
            assert!(command.contains(assertion), "missing {assertion}");
        }
        assert!(fixture.evidence_absent().await.expect("evidence state"));
        assert!(fixture.cleanup().await.expect("fixture cleanup"));
        assert!(!PathBuf::from(base.directory())
            .join(".a3s-oci-rootfs-output-fixture-123")
            .exists());
    }
}
