use std::process::ExitCode;

fn main() -> ExitCode {
    let result = match a3s_oci_agent::run_internal_container_init() {
        Some(result) => result,
        None => a3s_oci_agent::mount_runtime_share_if_requested()
            .and_then(|runtime_parent| {
                a3s_oci_agent::take_vm_attachment_manifest(runtime_parent.as_deref())
                    .map(|attachments| (runtime_parent, attachments))
            })
            .and_then(|(runtime_parent, attachments)| {
                a3s_oci_agent::take_session_token()
                    .map(|token| (runtime_parent, attachments, token))
            })
            .and_then(|(runtime_parent, attachments, token)| {
                a3s_oci_agent::take_transport_qualification_request().and_then(|qualification| {
                    match (qualification, attachments) {
                        (Some(_), Some(_)) => Err(a3s_oci_sdk::Error::new(
                            a3s_oci_sdk::ErrorCode::FailedPrecondition,
                            "transport qualification cannot consume production VM attachments",
                        )
                        .for_operation("bootstrap-guest-agent")),
                        (Some(request), None) => a3s_oci_agent::run_transport_qualification(
                            token,
                            request,
                            runtime_parent,
                        ),
                        (None, attachments) => a3s_oci_agent::run_with_vm_attachments(
                            token,
                            runtime_parent,
                            attachments,
                        ),
                    }
                })
            }),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("a3s-oci-agent: {error}");
            ExitCode::FAILURE
        }
    }
}
