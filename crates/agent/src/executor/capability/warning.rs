use a3s_oci_sdk::{Result, OCI_LINUX_CAPABILITY_NAMES};
use serde::{Deserialize, Serialize};

use super::{invalid, CapabilityPlan};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(in crate::executor) enum CapabilitySet {
    Bounding,
    Effective,
    Inheritable,
    Permitted,
    Ambient,
}

impl CapabilitySet {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Bounding => "bounding",
            Self::Effective => "effective",
            Self::Inheritable => "inheritable",
            Self::Permitted => "permitted",
            Self::Ambient => "ambient",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::executor) struct CapabilityWarning {
    capability: String,
    unavailable_sets: Vec<CapabilitySet>,
}

impl CapabilityWarning {
    #[cfg(test)]
    pub(in crate::executor) fn new(
        capability: impl Into<String>,
        unavailable_sets: Vec<CapabilitySet>,
    ) -> Result<Self> {
        let warning = Self {
            capability: capability.into(),
            unavailable_sets,
        };
        warning.validate()?;
        Ok(warning)
    }

    pub(in crate::executor) fn validate(&self) -> Result<()> {
        if !OCI_LINUX_CAPABILITY_NAMES.contains(&self.capability.as_str()) {
            return Err(invalid(format!(
                "capability warning names an unrecognized capability {:?}",
                self.capability
            )));
        }
        if self.unavailable_sets.is_empty()
            || self
                .unavailable_sets
                .windows(2)
                .any(|sets| sets[0] >= sets[1])
        {
            return Err(invalid(
                "capability warning sets must be non-empty, unique, and canonically ordered",
            ));
        }
        Ok(())
    }

    pub(in crate::executor) fn capability(&self) -> &str {
        &self.capability
    }

    #[cfg(test)]
    pub(super) fn unavailable_sets(&self) -> &[CapabilitySet] {
        &self.unavailable_sets
    }

    pub(in crate::executor) fn message(&self) -> String {
        let sets = self
            .unavailable_sets
            .iter()
            .map(|set| set.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            concat!(
                "requested capability {} cannot be granted in process set(s) {}; ",
                "continuing with the remaining requested capabilities"
            ),
            self.capability, sets
        )
    }
}

pub(in crate::executor) fn report_capability_warnings(warnings: &[CapabilityWarning]) {
    for warning in warnings {
        eprintln!("a3s-oci-agent: capability warning: {}", warning.message());
    }
}

pub(super) fn capability_warnings(
    requested: CapabilityPlan,
    applied: CapabilityPlan,
) -> Vec<CapabilityWarning> {
    let sets = [
        (
            CapabilitySet::Bounding,
            requested.bounding,
            applied.bounding,
        ),
        (
            CapabilitySet::Effective,
            requested.effective,
            applied.effective,
        ),
        (
            CapabilitySet::Inheritable,
            requested.inheritable,
            applied.inheritable,
        ),
        (
            CapabilitySet::Permitted,
            requested.permitted,
            applied.permitted,
        ),
        (CapabilitySet::Ambient, requested.ambient, applied.ambient),
    ];
    OCI_LINUX_CAPABILITY_NAMES
        .iter()
        .enumerate()
        .filter_map(|(number, name)| {
            let bit = 1_u64 << number;
            let unavailable_sets = sets
                .iter()
                .filter_map(|(set, requested, applied)| {
                    (requested & bit != 0 && applied & bit == 0).then_some(*set)
                })
                .collect::<Vec<_>>();
            (!unavailable_sets.is_empty()).then(|| CapabilityWarning {
                capability: (*name).to_string(),
                unavailable_sets,
            })
        })
        .collect()
}
