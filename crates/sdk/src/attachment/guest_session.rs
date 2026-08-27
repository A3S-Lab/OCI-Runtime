use std::fmt;

use serde::{de, Deserialize, Deserializer, Serialize};

use super::invalid_attachment;
use crate::{GuestSessionId, IsolationClass, IsolationRequest, Result, TrustDomainId};

/// Maximum number of containers one reusable guest-session contract may admit.
pub const MAX_GUEST_SESSION_CAPACITY: u16 = 64;

/// Exact incarnation of one logical reusable guest session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct GuestSessionGeneration(u64);

impl GuestSessionGeneration {
    /// Construct a positive guest-session generation fence.
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            return Err(invalid_attachment(
                "guest-session generation must be greater than zero",
            ));
        }
        Ok(Self(value))
    }

    /// Numeric generation value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for GuestSessionGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl<'de> Deserialize<'de> for GuestSessionGeneration {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// Bounded member capacity for one guest-session incarnation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct GuestSessionCapacity(u16);

impl GuestSessionCapacity {
    /// Construct a positive capacity within the runtime's fixed session bound.
    pub fn new(value: u16) -> Result<Self> {
        if !(1..=MAX_GUEST_SESSION_CAPACITY).contains(&value) {
            return Err(invalid_attachment(format!(
                "guest-session capacity must be between 1 and {MAX_GUEST_SESSION_CAPACITY}"
            )));
        }
        Ok(Self(value))
    }

    /// Maximum simultaneous container members.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl fmt::Display for GuestSessionCapacity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl<'de> Deserialize<'de> for GuestSessionCapacity {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u16::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// Authority that owns the actual guest process and kernel lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuestSessionOwnership {
    /// OCI Runtime owns the VM/session mechanism; callers retain pool policy.
    Runtime,
}

/// Empty-session behavior within one immutable trust-domain generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuestSessionReset {
    /// Destroy the guest when its final member is deleted.
    DestroyOnEmpty,
    /// Retain an empty guest only for the same immutable trust domain.
    RetainWithinTrustDomain,
}

/// Exact reusable guest-session ownership bound to one create request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuestSessionAttachment {
    id: GuestSessionId,
    generation: GuestSessionGeneration,
    trust_domain: TrustDomainId,
    isolation: IsolationClass,
    capacity: GuestSessionCapacity,
    reset: GuestSessionReset,
    ownership: GuestSessionOwnership,
}

impl GuestSessionAttachment {
    pub(super) fn new(
        id: GuestSessionId,
        generation: GuestSessionGeneration,
        trust_domain: TrustDomainId,
        capacity: GuestSessionCapacity,
        reset: GuestSessionReset,
    ) -> Self {
        Self {
            id,
            generation,
            trust_domain,
            isolation: IsolationClass::SharedGuestKernel,
            capacity,
            reset,
            ownership: GuestSessionOwnership::Runtime,
        }
    }

    /// Caller-issued logical reusable-session identity.
    #[must_use]
    pub const fn id(&self) -> &GuestSessionId {
        &self.id
    }

    /// Exact reusable-session incarnation.
    #[must_use]
    pub const fn generation(&self) -> GuestSessionGeneration {
        self.generation
    }

    /// Immutable caller-declared trust domain for this incarnation.
    #[must_use]
    pub const fn trust_domain(&self) -> &TrustDomainId {
        &self.trust_domain
    }

    /// Required kernel-sharing boundary.
    #[must_use]
    pub const fn isolation(&self) -> IsolationClass {
        self.isolation
    }

    /// Maximum simultaneous member count.
    #[must_use]
    pub const fn capacity(&self) -> GuestSessionCapacity {
        self.capacity
    }

    /// Empty-session behavior.
    #[must_use]
    pub const fn reset(&self) -> GuestSessionReset {
        self.reset
    }

    /// Authority that owns the actual guest lifetime.
    #[must_use]
    pub const fn ownership(&self) -> GuestSessionOwnership {
        self.ownership
    }

    pub(super) fn validate(&self) -> Result<()> {
        if self.isolation != IsolationClass::SharedGuestKernel {
            return Err(invalid_attachment(
                "a reusable guest session requires shared-guest-kernel isolation",
            ));
        }
        Ok(())
    }

    pub(super) fn validate_isolation(&self, isolation: &IsolationRequest) -> Result<()> {
        let IsolationRequest::SharedGuestKernel { trust_domain } = isolation else {
            return Err(invalid_attachment(
                "a reusable guest session requires shared-guest-kernel isolation",
            ));
        };
        if trust_domain != &self.trust_domain {
            return Err(invalid_attachment(format!(
                "reusable guest-session trust domain {} differs from create trust domain {}",
                self.trust_domain, trust_domain
            )));
        }
        Ok(())
    }
}
