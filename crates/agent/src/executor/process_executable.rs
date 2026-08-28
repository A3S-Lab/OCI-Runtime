use std::ffi::{CStr, CString};
use std::io;
use std::os::raw::c_char;

const DEFAULT_PATH: &[u8] = b"/bin:/usr/bin";

/// Replaces the current process using the OCI `execvp` file semantics.
///
/// The configured environment is used for both `PATH` lookup and the final
/// process image. All pointers are derived from live `CString` values and stay
/// valid until a successful `execve` replaces the process.
pub(super) fn execute(arguments: &[CString], environment: &[CString]) -> io::Error {
    let Some(file) = arguments.first() else {
        return io::Error::from_raw_os_error(libc::EINVAL);
    };
    let argument_pointers = pointer_vector(arguments);
    let environment_pointers = pointer_vector(environment);

    if file.as_bytes().contains(&b'/') {
        return execute_candidate(file, &argument_pointers, &environment_pointers);
    }

    let path = configured_path(environment).unwrap_or(DEFAULT_PATH);
    let mut permission_denied = None;
    for directory in path.split(|byte| *byte == b':') {
        let candidate = match path_candidate(directory, file) {
            Ok(candidate) => candidate,
            Err(error) => return error,
        };
        let error = execute_candidate(&candidate, &argument_pointers, &environment_pointers);
        match error.raw_os_error() {
            Some(libc::EACCES) => permission_denied = Some(error),
            Some(libc::ENOENT | libc::ENOTDIR) => {}
            _ => return error,
        }
    }
    permission_denied.unwrap_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))
}

fn configured_path(environment: &[CString]) -> Option<&[u8]> {
    environment
        .iter()
        .find_map(|entry| entry.as_bytes().strip_prefix(b"PATH="))
}

fn path_candidate(directory: &[u8], file: &CStr) -> io::Result<CString> {
    if directory.is_empty() {
        return Ok(file.to_owned());
    }
    let mut candidate = Vec::with_capacity(directory.len() + file.to_bytes().len() + 1);
    candidate.extend_from_slice(directory);
    candidate.push(b'/');
    candidate.extend_from_slice(file.to_bytes());
    CString::new(candidate).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

fn pointer_vector(values: &[CString]) -> Vec<*const c_char> {
    values
        .iter()
        .map(|value| value.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect()
}

fn execute_candidate(
    candidate: &CStr,
    arguments: &[*const c_char],
    environment: &[*const c_char],
) -> io::Error {
    // SAFETY: all three pointer trees reference live NUL-terminated values,
    // and both pointer vectors end in a null sentinel.
    unsafe {
        libc::execve(candidate.as_ptr(), arguments.as_ptr(), environment.as_ptr());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOEXEC) {
        execute_with_shell(candidate, arguments, environment)
    } else {
        error
    }
}

fn execute_with_shell(
    candidate: &CStr,
    arguments: &[*const c_char],
    environment: &[*const c_char],
) -> io::Error {
    let shell = c"/bin/sh";
    let mut shell_arguments = Vec::with_capacity(arguments.len() + 1);
    shell_arguments.push(shell.as_ptr());
    shell_arguments.push(candidate.as_ptr());
    if arguments.len() > 2 {
        shell_arguments.extend_from_slice(&arguments[1..arguments.len() - 1]);
    }
    shell_arguments.push(std::ptr::null());
    // SAFETY: the shell and candidate are live C strings, the remaining
    // arguments and environment retain their original live backing storage,
    // and both pointer vectors end in a null sentinel.
    unsafe {
        libc::execve(
            shell.as_ptr(),
            shell_arguments.as_ptr(),
            environment.as_ptr(),
        );
    }
    io::Error::last_os_error()
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::os::unix::fs::symlink;
    use std::process::Command;

    use super::execute;

    const CHILD_ENV: &str = "A3S_OCI_EXECVP_TEST_CHILD";
    const PATH_ENV: &str = "A3S_OCI_EXECVP_TEST_PATH";

    #[test]
    fn executes_a_file_from_the_configured_path_in_an_isolated_process() {
        match std::env::var(CHILD_ENV).as_deref() {
            Ok("lookup") => {
                let path = std::env::var(PATH_ENV).expect("read isolated executable path");
                let arguments = [
                    "a3s-oci-execvp-test",
                    "executor::process_executable::tests::executes_a_file_from_the_configured_path_in_an_isolated_process",
                    "--exact",
                ]
                .map(|value| CString::new(value).expect("prepare isolated argument"));
                let environment = [format!("PATH={path}"), format!("{CHILD_ENV}=executed")]
                    .map(|value| CString::new(value).expect("prepare isolated environment"));
                let error = execute(&arguments, &environment);
                panic!("configured PATH execution failed: {error}");
            }
            Ok("executed") => return,
            _ => {}
        }

        let directory = tempfile::tempdir().expect("create isolated executable directory");
        let executable = std::env::current_exe().expect("resolve current test executable");
        symlink(&executable, directory.path().join("a3s-oci-execvp-test"))
            .expect("link isolated executable into configured PATH");
        let output = Command::new(executable)
            .arg("executor::process_executable::tests::executes_a_file_from_the_configured_path_in_an_isolated_process")
            .arg("--exact")
            .arg("--nocapture")
            .env(CHILD_ENV, "lookup")
            .env(PATH_ENV, directory.path())
            .output()
            .expect("spawn isolated execvp test process");
        assert!(
            output.status.success(),
            "isolated execvp process failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn path_candidates_preserve_absolute_relative_and_empty_components() {
        let file = CString::new("tool").expect("prepare file");
        assert_eq!(
            super::path_candidate(b"/custom/bin", &file)
                .expect("build absolute candidate")
                .to_bytes(),
            b"/custom/bin/tool"
        );
        assert_eq!(
            super::path_candidate(b"relative", &file)
                .expect("build relative candidate")
                .to_bytes(),
            b"relative/tool"
        );
        assert_eq!(
            super::path_candidate(b"", &file)
                .expect("build current-directory candidate")
                .to_bytes(),
            b"tool"
        );
    }
}
