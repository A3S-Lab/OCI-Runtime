use std::ffi::{c_char, CString};
use std::path::Path;
use std::ptr;

use a3s_oci_sdk::{Error, ErrorCode, Result};
use zeroize::Zeroizing;

// The pinned libkrun reads exactly MAX_ARGS pointer slots with
// `slice::from_raw_parts`, even when a caller supplies only a few entries.
// Keep this value synchronized with the retained native source.
const LIBKRUN_MAX_ARGS: usize = 4_096;

pub(crate) fn path_to_cstring(operation: &'static str, path: &Path) -> Result<CString> {
    let value = path.to_str().ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("path is not valid UTF-8: {}", path.display()),
        )
        .for_operation(operation)
    })?;
    value_to_cstring(operation, "path", value)
}

pub(crate) fn value_to_cstring(
    operation: &'static str,
    description: &'static str,
    value: &str,
) -> Result<CString> {
    CString::new(value).map_err(|_| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("{description} contains an embedded NUL byte"),
        )
        .for_operation(operation)
    })
}

#[derive(Debug)]
pub(crate) struct FfiStringArray {
    _storage: Vec<Zeroizing<Vec<u8>>>,
    pointers: Vec<*const c_char>,
}

impl FfiStringArray {
    pub(crate) fn new(
        operation: &'static str,
        description: &'static str,
        values: &[String],
    ) -> Result<Self> {
        if values.len() >= LIBKRUN_MAX_ARGS {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "{description} contains {} entries; libkrun accepts at most {}",
                    values.len(),
                    LIBKRUN_MAX_ARGS - 1
                ),
            )
            .for_operation(operation));
        }

        let storage = values
            .iter()
            .map(|value| {
                value_to_cstring(operation, description, value)
                    .map(CString::into_bytes_with_nul)
                    .map(Zeroizing::new)
            })
            .collect::<Result<Vec<_>>>()?;
        let mut pointers = vec![ptr::null(); LIBKRUN_MAX_ARGS];
        for (slot, value) in pointers.iter_mut().zip(&storage) {
            *slot = value.as_ptr().cast();
        }

        Ok(Self {
            _storage: storage,
            pointers,
        })
    }

    pub(crate) fn as_ptr(&self) -> *const *const c_char {
        self.pointers.as_ptr()
    }
}

#[cfg(test)]
mod tests {
    use super::{FfiStringArray, LIBKRUN_MAX_ARGS};

    #[test]
    fn ffi_array_allocates_the_full_libkrun_pointer_table() {
        let values = vec!["-c".to_string(), "exit 0".to_string()];
        let array = FfiStringArray::new("test", "arguments", &values).expect("array must be valid");

        assert_eq!(array.pointers.len(), LIBKRUN_MAX_ARGS);
        assert!(!array.pointers[0].is_null());
        assert!(!array.pointers[1].is_null());
        assert!(array.pointers[2..].iter().all(|pointer| pointer.is_null()));
    }

    #[test]
    fn ffi_array_reserves_one_null_terminator_slot() {
        let values = vec![String::new(); LIBKRUN_MAX_ARGS];
        let error = FfiStringArray::new("test", "arguments", &values)
            .expect_err("oversized arrays must be rejected");

        assert!(error.to_string().contains("at most 4095"));
    }
}
