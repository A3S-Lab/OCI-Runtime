use std::process::ExitCode;

fn main() -> ExitCode {
    match a3s_oci_agent::take_session_token_from_environment().and_then(a3s_oci_agent::run) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("a3s-oci-agent: {error}");
            ExitCode::FAILURE
        }
    }
}
