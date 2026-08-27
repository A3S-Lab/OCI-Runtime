use std::collections::BTreeMap;
use std::sync::Arc;

use a3s_oci_sdk::{
    ContainerId, ContainerTarget, ExitStatus, Generation, GuestSessionAttachment, GuestSessionId,
};

use super::{AgentDriverClient, UtilityVmOwner};

#[derive(Default)]
pub(super) struct UtilityVmRegistry {
    pub(super) attachments: BTreeMap<ContainerId, UtilityVmAttachment>,
    pub(super) reusable: BTreeMap<GuestSessionId, ReusableGuestSession>,
}

impl UtilityVmRegistry {
    pub(super) fn live_guests(&self) -> Vec<Arc<UtilityVmGuest>> {
        let mut guests = Vec::new();
        for attachment in self.attachments.values() {
            if let UtilityVmAttachment::Live(container) = attachment {
                push_unique(&mut guests, &container.guest);
            }
        }
        for session in self.reusable.values() {
            push_unique(&mut guests, &session.guest);
        }
        guests
    }

    pub(super) fn active_guest_count(&self) -> usize {
        self.live_guests().len()
    }

    pub(super) fn attachment_count_for_session(&self, expected: &GuestSessionAttachment) -> usize {
        self.attachments
            .values()
            .filter(|attachment| attachment.guest_session() == Some(expected))
            .count()
    }
}

fn push_unique(guests: &mut Vec<Arc<UtilityVmGuest>>, candidate: &Arc<UtilityVmGuest>) {
    if !guests
        .iter()
        .any(|retained| Arc::ptr_eq(retained, candidate))
    {
        guests.push(Arc::clone(candidate));
    }
}

#[derive(Clone)]
pub(super) enum UtilityVmAttachment {
    Live(Arc<UtilityVmContainer>),
    RecoveredStopped {
        target: ContainerTarget,
        guest_session: Option<GuestSessionAttachment>,
        init_exit_status: Option<ExitStatus>,
    },
}

impl UtilityVmAttachment {
    pub(super) fn target(&self) -> &ContainerTarget {
        match self {
            Self::Live(container) => &container.target,
            Self::RecoveredStopped { target, .. } => target,
        }
    }

    pub(super) fn guest_session(&self) -> Option<&GuestSessionAttachment> {
        match self {
            Self::Live(container) => container.guest_session.as_ref(),
            Self::RecoveredStopped { guest_session, .. } => guest_session.as_ref(),
        }
    }
}

pub(super) struct UtilityVmContainer {
    pub(super) target: ContainerTarget,
    pub(super) guest_session: Option<GuestSessionAttachment>,
    pub(super) guest: Arc<UtilityVmGuest>,
}

pub(super) struct UtilityVmGuest {
    pub(super) client: AgentDriverClient,
    pub(super) owner: Arc<dyn UtilityVmOwner>,
}

pub(super) struct ReusableGuestSession {
    pub(super) attachment: GuestSessionAttachment,
    pub(super) guest: Arc<UtilityVmGuest>,
    pub(super) members: BTreeMap<ContainerId, Generation>,
}

impl ReusableGuestSession {
    pub(super) fn new(
        attachment: GuestSessionAttachment,
        guest: Arc<UtilityVmGuest>,
        target: &ContainerTarget,
    ) -> Self {
        let mut members = BTreeMap::new();
        members.insert(
            target.id.clone(),
            target
                .generation
                .expect("utility-VM session admission requires an exact generation"),
        );
        Self {
            attachment,
            guest,
            members,
        }
    }
}
