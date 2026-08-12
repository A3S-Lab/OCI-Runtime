use std::process::ExitCode;

fn main() -> ExitCode {
    let result = match a3s_oci_agent::run_internal_container_init() {
        Some(result) => result,
        None => a3s_oci_agent::mount_runtime_share_if_requested()
            .and_then(|runtime_parent| {
                a3s_oci_agent::take_session_token().map(|token| (runtime_parent, token))
            })
            .and_then(|(runtime_parent, token)| {
                a3s_oci_agent::take_transport_qualification_request().and_then(|qualification| {
                    match qualification {
                        Some(request) => a3s_oci_agent::run_transport_qualification(
                            token,
                            request,
                            runtime_parent,
                        ),
                        None => a3s_oci_agent::run(token, runtime_parent),
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
