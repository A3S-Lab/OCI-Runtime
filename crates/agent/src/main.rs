use std::process::ExitCode;

fn main() -> ExitCode {
    let result = match a3s_oci_agent::run_internal_container_init() {
        Some(result) => result,
        None => a3s_oci_agent::take_session_token_from_environment().and_then(a3s_oci_agent::run),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("a3s-oci-agent: {error}");
            ExitCode::FAILURE
        }
    }
}
