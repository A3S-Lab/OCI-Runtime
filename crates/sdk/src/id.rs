use std::fmt::{self, Display};
use std::str::FromStr;

use serde::{de, Deserialize, Deserializer, Serialize};

use crate::{Error, ErrorCode, Result};

const MAX_IDENTIFIER_BYTES: usize = 128;

fn validate_identifier(kind: &str, value: String) -> Result<String> {
    if value.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("{kind} must not be empty"),
        ));
    }
    if value.len() > MAX_IDENTIFIER_BYTES {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("{kind} must be at most {MAX_IDENTIFIER_BYTES} bytes"),
        ));
    }

    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("{kind} must not be empty"),
        ));
    };
    if !first.is_ascii_alphanumeric() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("{kind} must start with an ASCII letter or digit"),
        ));
    }
    if !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'+' | b'-'))
    {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("{kind} contains a character that is unsafe in a runtime path"),
        ));
    }

    Ok(value)
}

macro_rules! identifier {
    ($name:ident, $label:literal) => {
        #[doc = concat!("Validated ", $label, ".")]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            #[doc = concat!("Validate and construct a ", $label, ".")]
            pub fn new(value: impl Into<String>) -> Result<Self> {
                validate_identifier($label, value.into()).map(Self)
            }

            #[doc = concat!("Borrow the ", $label, " as a string.")]
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl FromStr for $name {
            type Err = Error;

            fn from_str(value: &str) -> Result<Self> {
                Self::new(value)
            }
        }

        impl TryFrom<String> for $name {
            type Error = Error;

            fn try_from(value: String) -> Result<Self> {
                Self::new(value)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(de::Error::custom)
            }
        }
    };
}

identifier!(ContainerId, "container ID");
identifier!(ProcessId, "process ID");
identifier!(OperationId, "operation ID");
identifier!(TrustDomainId, "trust-domain ID");

/// Monotonic incarnation of a container ID used to reject stale retries.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Generation(pub u64);

#[cfg(test)]
mod tests {
    use super::{ContainerId, Generation};

    #[test]
    fn accepts_path_safe_identifier() {
        let id = ContainerId::new("box_01.worker+test").expect("ID should be valid");
        assert_eq!(id.as_str(), "box_01.worker+test");
    }

    #[test]
    fn rejects_path_traversal_and_separators() {
        for value in ["../box", "/box", "box/child", r"box\child", "-box", ""] {
            assert!(
                ContainerId::new(value).is_err(),
                "{value:?} must be rejected"
            );
        }
    }

    #[test]
    fn deserialization_cannot_bypass_validation() {
        let error = serde_json::from_str::<ContainerId>(r#""../box""#)
            .expect_err("invalid serialized ID must be rejected");
        assert!(error.to_string().contains("container ID"));
    }

    #[test]
    fn generation_round_trips_as_a_number() {
        let encoded = serde_json::to_string(&Generation(42)).expect("serialize generation");
        assert_eq!(encoded, "42");
        assert_eq!(
            serde_json::from_str::<Generation>(&encoded).expect("deserialize generation"),
            Generation(42)
        );
    }
}
