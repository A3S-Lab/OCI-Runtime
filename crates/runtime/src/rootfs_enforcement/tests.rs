use std::path::PathBuf;

use a3s_oci_sdk::OciBundle;
use serde_json::Value;
use tempfile::tempdir;

use super::{build_bundle, EnforcementIdMappings, FixtureIdMapping, RootfsEnforcementFixture};

const CONFIG: &str = include_str!("../../../../fixtures/utility-vm/config.json");
const NATIVE_CONFIG: &str = include_str!("../../../../fixtures/native-linux/config.json");

fn mount_at<'a>(mounts: &'a [Value], destination: &str) -> &'a Value {
    mounts
        .iter()
        .find(|mount| mount["destination"] == destination)
        .unwrap_or_else(|| panic!("missing mount at {destination}"))
}

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
        config["linux"]["uidMappings"],
        serde_json::json!([{"containerID": 0, "hostID": 0, "size": 65_536}])
    );
    assert_eq!(
        config["linux"]["gidMappings"],
        serde_json::json!([{"containerID": 0, "hostID": 0, "size": 65_536}])
    );
    assert_eq!(
        config["process"]["capabilities"],
        serde_json::json!({
            "bounding": ["CAP_SYS_PTRACE"],
            "effective": ["CAP_SYS_PTRACE"],
            "inheritable": [],
            "permitted": ["CAP_SYS_PTRACE"],
            "ambient": []
        })
    );
    let mounts = config["mounts"].as_array().expect("mount array");
    let dev_mount = mount_at(mounts, "/dev");
    assert_eq!(dev_mount["type"], "tmpfs");
    assert_eq!(dev_mount["source"], "tmpfs");
    assert_eq!(
        dev_mount["options"],
        serde_json::json!(["nosuid", "strictatime", "mode=0755", "size=64k"])
    );
    assert_eq!(
        mount_at(mounts, "/.a3s-oci-rootfs-target-fixture-123/output")["source"],
        Value::String(".a3s-oci-rootfs-output-fixture-123".into())
    );
    assert_eq!(
        mount_at(mounts, "/.a3s-oci-rootfs-target-fixture-123/bound-file")["source"],
        Value::String(".a3s-oci-rootfs-output-fixture-123/bind-source".into())
    );
    let recursive_mount = mount_at(
        mounts,
        "/.a3s-oci-rootfs-target-fixture-123/recursive/readonly",
    );
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
    let idmapped_mounts = mounts
        .iter()
        .filter(|mount| {
            mount["options"].as_array().is_some_and(|options| {
                options
                    .iter()
                    .any(|option| matches!(option.as_str(), Some("idmap" | "ridmap")))
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(idmapped_mounts.len(), 2);
    assert_eq!(
        idmapped_mounts[0]["uidMappings"],
        serde_json::json!([{"containerID": 0, "hostID": 1000, "size": 1}])
    );
    assert_eq!(
        idmapped_mounts[1]["uidMappings"],
        serde_json::json!([{"containerID": 0, "hostID": 2000, "size": 1}])
    );
    let command = config["process"]["args"][2]
        .as_str()
        .expect("enforcement command");
    for assertion in [
        "/bin/busybox setsid /bin/busybox setsid",
        "pid1-supervision-enforced",
        "orphan-adopted-by-pid1",
        "orphan-reaping-enforced",
        "failure_step=dev-symlinks",
        "readlink /dev/fd",
        "readlink /dev/stderr",
        "dev-symlinks-verified",
        "mount-target-created",
        "mount-file-target-created",
        "rootfs-propagation-shared",
        "readonly-path-enforced",
        "masked-directory-empty-readonly",
        "masked-path-enforced",
        "recursive-mount-attributes-enforced",
        "idmapped-mounts-enforced",
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

#[test]
fn utility_vm_fixture_preserves_caller_owned_root_and_extends_id_range() {
    let temporary = tempdir().expect("temporary utility-VM fixture");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir_all(bundle_directory.join("rootfs")).expect("fixture rootfs");
    let mut config: Value = serde_json::from_str(CONFIG).expect("utility-VM config");
    config["linux"]["uidMappings"] =
        serde_json::json!([{"containerID": 0, "hostID": 501, "size": 1}]);
    config["linux"]["gidMappings"] =
        serde_json::json!([{"containerID": 0, "hostID": 0, "size": 1}]);
    let base = OciBundle::from_json(
        bundle_directory,
        serde_json::to_string(&config).expect("caller-owned config JSON"),
    )
    .expect("caller-owned utility-VM base bundle");

    let mappings =
        EnforcementIdMappings::from_base(&base, false).expect("extended fixture mappings");
    assert_eq!(
        mappings.uids,
        vec![
            FixtureIdMapping {
                container_id: 0,
                host_id: 501,
                size: 1,
            },
            FixtureIdMapping {
                container_id: 1,
                host_id: 0,
                size: 501,
            },
            FixtureIdMapping {
                container_id: 502,
                host_id: 502,
                size: 65_034,
            },
        ]
    );
    assert_eq!(
        mappings.gids,
        vec![FixtureIdMapping {
            container_id: 0,
            host_id: 0,
            size: 65_536,
        }]
    );
    assert_mapping_ranges_do_not_overlap(&mappings.uids);
    assert_mapping_ranges_do_not_overlap(&mappings.gids);
    for (container_id, expected_uid, expected_gid) in [
        (0, 501, 0),
        (1, 0, 1),
        (501, 500, 501),
        (1_000, 1_000, 1_000),
        (2_000, 2_000, 2_000),
        (65_535, 65_535, 65_535),
    ] {
        assert_eq!(
            super::translate_fixture_id(&mappings.uids, container_id, "UID").expect("visible UID"),
            expected_uid
        );
        assert_eq!(
            super::translate_fixture_id(&mappings.gids, container_id, "GID").expect("visible GID"),
            expected_gid
        );
    }
    assert_eq!(
        mappings.filesystem_1000.uid,
        super::single_mapping(0, 1_000)
    );
    assert_eq!(
        mappings.filesystem_1000.gid,
        super::single_mapping(0, 1_000)
    );
    assert_eq!(
        mappings.filesystem_2000.uid,
        super::single_mapping(0, 2_000)
    );
    assert_eq!(
        mappings.filesystem_2000.gid,
        super::single_mapping(0, 2_000)
    );
}

fn assert_mapping_ranges_do_not_overlap(mappings: &[FixtureIdMapping]) {
    for (index, mapping) in mappings.iter().enumerate() {
        let container_end = u64::from(mapping.container_id) + u64::from(mapping.size);
        let host_end = u64::from(mapping.host_id) + u64::from(mapping.size);
        for prior in &mappings[..index] {
            let prior_container_end = u64::from(prior.container_id) + u64::from(prior.size);
            let prior_host_end = u64::from(prior.host_id) + u64::from(prior.size);
            assert!(
                container_end <= u64::from(prior.container_id)
                    || prior_container_end <= u64::from(mapping.container_id),
                "container ranges overlap: {prior:?} and {mapping:?}"
            );
            assert!(
                host_end <= u64::from(prior.host_id)
                    || prior_host_end <= u64::from(mapping.host_id),
                "host ranges overlap: {prior:?} and {mapping:?}"
            );
        }
    }
}

#[test]
fn native_fixture_declares_ordered_idmap_and_ridmap_bind_evidence() {
    let temporary = tempdir().expect("temporary native fixture");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir_all(bundle_directory.join("rootfs")).expect("fixture rootfs");
    let base = OciBundle::from_json(bundle_directory, NATIVE_CONFIG)
        .expect("qualified native base bundle");
    let bundle = build_bundle(
        &base,
        ".a3s-oci-rootfs-output-native",
        ".a3s-oci-rootfs-target-native",
        "native",
        true,
    )
    .expect("native rootfs enforcement bundle");
    let config: Value =
        serde_json::from_str(bundle.config_json()).expect("native enforcement JSON");
    let mounts = config["mounts"].as_array().expect("mount array");

    assert_eq!(
        config["linux"]["uidMappings"],
        serde_json::json!([{"containerID": 0, "hostID": 100_000, "size": 65_536}])
    );
    assert_eq!(
        config["linux"]["gidMappings"],
        serde_json::json!([{"containerID": 0, "hostID": 200_000, "size": 65_536}])
    );

    let ordered_source = mounts
        .iter()
        .find(|mount| {
            mount["destination"]
                .as_str()
                .is_some_and(|path| path.ends_with("/recursive/source"))
        })
        .expect("ordered ID-map source mount");
    assert!(ordered_source["options"]
        .as_array()
        .is_some_and(|options| options.iter().any(|option| option == "mode=0755")));

    for (destination, mapped_uid, mapped_gid) in [
        ("/idmap/filesystem/nonrecursive", 101_000, 201_000),
        ("/idmap/filesystem/recursive", 102_000, 202_000),
    ] {
        let mount = mounts
            .iter()
            .find(|mount| {
                mount["destination"]
                    .as_str()
                    .is_some_and(|path| path.ends_with(destination))
            })
            .expect("native ID-mapped filesystem mount");
        assert_eq!(mount["uidMappings"][0]["containerID"], 0);
        assert_eq!(mount["uidMappings"][0]["hostID"], mapped_uid);
        assert_eq!(mount["gidMappings"][0]["containerID"], 0);
        assert_eq!(mount["gidMappings"][0]["hostID"], mapped_gid);
    }

    for (destination, mode, mapped_uid, mapped_gid) in [
        ("/idmap/bind/nonrecursive", "idmap", 101_000, 201_000),
        ("/idmap/bind/recursive", "ridmap", 102_000, 202_000),
    ] {
        let mount = mounts
            .iter()
            .find(|mount| {
                mount["destination"]
                    .as_str()
                    .is_some_and(|path| path.ends_with(destination))
            })
            .expect("native ID-mapped bind mount");
        assert!(mount["options"]
            .as_array()
            .is_some_and(|options| options.iter().any(|option| option == mode)));
        assert!(mount["source"]
            .as_str()
            .is_some_and(|source| source.ends_with("/recursive/source")));
        assert_eq!(mount["uidMappings"][0]["containerID"], 0);
        assert_eq!(mount["uidMappings"][0]["hostID"], mapped_uid);
        assert_eq!(mount["gidMappings"][0]["containerID"], 0);
        assert_eq!(mount["gidMappings"][0]["hostID"], mapped_gid);
    }
    assert!(!mounts.iter().any(|mount| {
        mount["destination"]
            .as_str()
            .is_some_and(|path| path.ends_with("/idmap/bind/source"))
    }));

    let command = config["process"]["args"][2]
        .as_str()
        .expect("native enforcement command");
    for assertion in [
        "idmap-source-ownership-unchanged",
        "idmap-nonrecursive-enforced",
        "ridmap-recursive-enforced",
    ] {
        assert!(command.contains(assertion), "missing {assertion}");
    }
}
