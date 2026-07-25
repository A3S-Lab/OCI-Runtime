use std::path::PathBuf;

use a3s_oci_sdk::{OciBundle, OciSemanticPhase};

const A3S_BOX_CONFIG: &str = include_str!("../../../fixtures/a3s-box/config.json");
const A3S_BOX_ROOTFS: &str = "/var/lib/a3s/boxes/box-123/rootfs";

#[test]
fn loads_the_exact_a3s_box_compiler_output() {
    let bundle_directory = std::env::current_dir()
        .expect("current directory")
        .join("a3s-box-fixture");
    let bundle = OciBundle::from_json(bundle_directory, A3S_BOX_CONFIG)
        .expect("A3S Box compiler output must remain a valid OCI bundle");
    bundle
        .validate_for_phase(OciSemanticPhase::Start)
        .expect("A3S Box bundle must remain start-valid");

    assert_eq!(
        bundle.spec().root().as_ref().expect("root").path(),
        &PathBuf::from(A3S_BOX_ROOTFS)
    );
    let process = bundle.spec().process().as_ref().expect("process");
    assert_eq!(
        process.args().as_deref(),
        Some(["/sbin/init".to_string()].as_slice())
    );
    assert!(process
        .env()
        .as_deref()
        .expect("environment")
        .iter()
        .any(|entry| entry == "A3S_EXEC_LISTENER_FD=3"));

    let linux = bundle.spec().linux().as_ref().expect("Linux configuration");
    assert_eq!(
        linux.uid_mappings().as_deref().expect("UID mappings").len(),
        1
    );
    assert_eq!(
        linux.gid_mappings().as_deref().expect("GID mappings").len(),
        1
    );
    assert_eq!(
        linux
            .cgroups_path()
            .as_deref()
            .expect("cgroups path")
            .to_string_lossy(),
        "a3s-box/box-123"
    );
    assert!(linux.resources().is_some());
    assert!(linux.seccomp().is_some());
    assert_eq!(linux.devices().as_deref().expect("devices").len(), 6);
}
