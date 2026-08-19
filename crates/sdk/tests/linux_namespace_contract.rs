use a3s_oci_sdk::{OciSchemaDocument, OciSchemaValidator};
use serde_json::{json, Value};

fn configuration(linux: Value) -> Value {
    json!({
        "ociVersion": "1.3.0",
        "linux": linux
    })
}

#[test]
fn schema_requires_namespace_and_id_mapping_members() {
    let validator = OciSchemaValidator::new().expect("compile pinned OCI schemas");
    validator
        .validate(
            OciSchemaDocument::Configuration,
            &configuration(json!({
                "namespaces": [{"type": "user"}],
                "uidMappings": [{"containerID": 0, "hostID": 1000, "size": 1}],
                "gidMappings": [{"containerID": 0, "hostID": 2000, "size": 1}]
            })),
        )
        .expect("complete namespace and ID mappings must satisfy the pinned schema");

    for invalid_linux in [
        json!({"namespaces": [{}]}),
        json!({"uidMappings": [{"hostID": 1000, "size": 1}]}),
        json!({"uidMappings": [{"containerID": 0, "size": 1}]}),
        json!({"uidMappings": [{"containerID": 0, "hostID": 1000}]}),
        json!({"gidMappings": [{"hostID": 2000, "size": 1}]}),
        json!({"gidMappings": [{"containerID": 0, "size": 1}]}),
        json!({"gidMappings": [{"containerID": 0, "hostID": 2000}]}),
    ] {
        validator
            .validate(
                OciSchemaDocument::Configuration,
                &configuration(invalid_linux),
            )
            .expect_err("missing required namespace or ID-mapping members must fail");
    }
}

#[test]
fn schema_preserves_optional_time_offset_members() {
    let validator = OciSchemaValidator::new().expect("compile pinned OCI schemas");
    for time_offsets in [
        json!({}),
        json!({"monotonic": {}}),
        json!({"monotonic": {"secs": -7}}),
        json!({"boottime": {"nanosecs": 11}}),
        json!({
            "monotonic": {"secs": -7, "nanosecs": 11},
            "boottime": {"secs": 19, "nanosecs": 23}
        }),
    ] {
        validator
            .validate(
                OciSchemaDocument::Configuration,
                &configuration(json!({"timeOffsets": time_offsets})),
            )
            .expect("optional time offset members must satisfy the pinned schema");
    }
}
