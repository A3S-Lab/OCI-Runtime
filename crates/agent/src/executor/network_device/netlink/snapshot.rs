use super::*;

const IFF_LOWER_UP: u32 = 1 << 16;
const IFF_DORMANT: u32 = 1 << 17;
const VOLATILE_LINK_FLAGS: u32 = libc::IFF_RUNNING as u32 | IFF_LOWER_UP | IFF_DORMANT;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LinkSnapshot {
    pub(super) index: i32,
    pub(super) name: String,
    pub(super) link_type: u16,
    pub(super) flags: u32,
    pub(super) attributes: BTreeMap<u16, Vec<u8>>,
    pub(super) addresses: Vec<AddressSnapshot>,
}

impl LinkSnapshot {
    pub(super) fn is_up(&self) -> bool {
        self.flags & libc::IFF_UP as u32 != 0
    }

    pub(super) fn master(&self) -> Option<u32> {
        self.attributes
            .get(&IFLA_MASTER)
            .and_then(|value| value.get(..4))
            .map(|value| u32::from_ne_bytes(value.try_into().expect("four-byte slice")))
            .filter(|master| *master != 0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct AddressSnapshot {
    pub(super) family: u8,
    pub(super) prefix_length: u8,
    pub(super) flags: u32,
    pub(super) attributes: BTreeMap<u16, Vec<u8>>,
}

pub(super) fn verify_snapshot(
    before: &LinkSnapshot,
    actual: &LinkSnapshot,
    expected_up: bool,
    phase: &str,
) -> Result<()> {
    let stable_mask = !(VOLATILE_LINK_FLAGS | libc::IFF_UP as u32);
    let before_flags = before.flags & stable_mask;
    let actual_flags = actual.flags & stable_mask;
    let changed_attributes = before
        .attributes
        .keys()
        .chain(actual.attributes.keys())
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|kind| before.attributes.get(kind) != actual.attributes.get(kind))
        .collect::<Vec<_>>();
    let address_mismatch = before
        .addresses
        .iter()
        .zip(&actual.addresses)
        .position(|(expected, observed)| expected != observed)
        .or_else(|| {
            (before.addresses.len() != actual.addresses.len())
                .then_some(before.addresses.len().min(actual.addresses.len()))
        });
    let address_difference = address_mismatch.map(|index| {
        format!(
            "{:?}->{:?}",
            before.addresses.get(index),
            actual.addresses.get(index)
        )
    });
    if before.index != actual.index
        || before.link_type != actual.link_type
        || before_flags != actual_flags
        || actual.is_up() != expected_up
        || !changed_attributes.is_empty()
        || address_mismatch.is_some()
    {
        return Err(netlink_error(
            ErrorCode::FailedPrecondition,
            format!(
                "network interface `{}` did not preserve its identity, link attributes, and permanent global addresses {phase}: index {}->{}, type {}->{}, stable flags {before_flags:#x}->{actual_flags:#x}, up {}->{}, changed attributes {changed_attributes:?}, permanent global address counts {}->{} with first mismatch {address_difference:?}",
                before.name,
                before.index,
                actual.index,
                before.link_type,
                actual.link_type,
                before.is_up(),
                actual.is_up(),
                before.addresses.len(),
                actual.addresses.len(),
            ),
        ));
    }
    Ok(())
}
