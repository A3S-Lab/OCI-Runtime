use std::collections::{BTreeMap, BTreeSet};

#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use a3s_oci_agent_protocol::AgentVmAttachmentManifest;
use a3s_oci_sdk::Result;

use super::attachment_error;

// libc models ioctl request width differently for glibc and musl. These Linux
// socket requests fit both ABIs; bind them once to the target's exact type.
#[cfg(target_os = "linux")]
const SIOCGIFFLAGS_REQUEST: libc::Ioctl = libc::SIOCGIFFLAGS as libc::Ioctl;
#[cfg(target_os = "linux")]
const SIOCSIFFLAGS_REQUEST: libc::Ioctl = libc::SIOCSIFFLAGS as libc::Ioctl;
#[cfg(target_os = "linux")]
const SIOCSIFNAME_REQUEST: libc::Ioctl = libc::SIOCSIFNAME as libc::Ioctl;

#[cfg(target_os = "linux")]
pub(super) fn configure_guest_interfaces(manifest: &AgentVmAttachmentManifest) -> Result<()> {
    let inventory = interface_inventory()?;
    let steps = rename_plan(manifest, &inventory)?;
    if steps.is_empty() {
        return Ok(());
    }
    let socket = datagram_socket()?;
    for step in steps {
        rename_interface(&socket, &step.from, &step.to)?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RenameStep {
    pub(super) from: String,
    pub(super) to: String,
}

pub(super) fn rename_plan(
    manifest: &AgentVmAttachmentManifest,
    inventory: &BTreeMap<String, [u8; 6]>,
) -> Result<Vec<RenameStep>> {
    let mut names_by_mac = BTreeMap::<[u8; 6], Vec<&str>>::new();
    for (name, mac) in inventory {
        names_by_mac.entry(*mac).or_default().push(name);
    }
    let desired = manifest
        .network()
        .iter()
        .map(|attachment| attachment.tap_name())
        .collect::<BTreeSet<_>>();
    let mut mappings = Vec::new();
    for attachment in manifest.network() {
        let matches = names_by_mac
            .get(attachment.mac_address().as_bytes())
            .cloned()
            .unwrap_or_default();
        if matches.len() != 1 {
            return Err(attachment_error(format!(
                "Guest must expose exactly one interface for KVM TAP {} MAC {:?}; found {}",
                attachment.tap_name(),
                attachment.mac_address().as_bytes(),
                matches.len()
            )));
        }
        let current = matches[0];
        mappings.push((current.to_string(), attachment.tap_name().to_string()));
    }
    let moving_sources = mappings
        .iter()
        .filter(|(current, desired)| current != desired)
        .map(|(current, _)| current.as_str())
        .collect::<BTreeSet<_>>();
    for (current, target) in &mappings {
        if current != target
            && inventory.contains_key(target)
            && !moving_sources.contains(target.as_str())
        {
            return Err(attachment_error(format!(
                "Guest interface name {target} is already occupied by an unrelated device"
            )));
        }
    }
    let moves = mappings
        .into_iter()
        .filter(|(current, desired)| current != desired)
        .collect::<Vec<_>>();

    let mut reserved = inventory.keys().cloned().collect::<BTreeSet<_>>();
    reserved.extend(desired.into_iter().map(str::to_string));
    let mut staged = Vec::with_capacity(moves.len());
    for (index, (current, desired)) in moves.into_iter().enumerate() {
        let temporary = (0_u32..=u32::MAX)
            .map(|attempt| format!("a3svm{index:03x}{attempt:03x}"))
            .find(|candidate| candidate.len() <= 15 && !reserved.contains(candidate))
            .ok_or_else(|| attachment_error("failed to allocate a temporary Guest NIC name"))?;
        reserved.insert(temporary.clone());
        staged.push((current, temporary, desired));
    }
    let mut steps = Vec::with_capacity(staged.len() * 2);
    steps.extend(staged.iter().map(|(current, temporary, _)| RenameStep {
        from: current.clone(),
        to: temporary.clone(),
    }));
    steps.extend(
        staged
            .into_iter()
            .map(|(_, temporary, desired)| RenameStep {
                from: temporary,
                to: desired,
            }),
    );
    Ok(steps)
}

#[cfg(target_os = "linux")]
fn interface_inventory() -> Result<BTreeMap<String, [u8; 6]>> {
    let mut inventory = BTreeMap::new();
    let entries = std::fs::read_dir("/sys/class/net").map_err(|error| {
        attachment_error(format!(
            "failed to enumerate Guest network interfaces: {error}"
        ))
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            attachment_error(format!(
                "failed to enumerate a Guest network interface: {error}"
            ))
        })?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let encoded = std::fs::read_to_string(entry.path().join("address")).map_err(|error| {
            attachment_error(format!(
                "failed to read Guest interface {name} MAC address: {error}"
            ))
        })?;
        inventory.insert(name, parse_mac(encoded.trim())?);
    }
    Ok(inventory)
}

#[cfg(target_os = "linux")]
fn parse_mac(value: &str) -> Result<[u8; 6]> {
    let fields = value.split(':').collect::<Vec<_>>();
    if fields.len() != 6 {
        return Err(attachment_error(format!(
            "Guest interface exposes invalid MAC address {value:?}"
        )));
    }
    let mut bytes = [0_u8; 6];
    for (slot, field) in bytes.iter_mut().zip(fields) {
        if field.len() != 2 {
            return Err(attachment_error(format!(
                "Guest interface exposes invalid MAC address {value:?}"
            )));
        }
        *slot = u8::from_str_radix(field, 16).map_err(|error| {
            attachment_error(format!(
                "Guest interface exposes invalid MAC address {value:?}: {error}"
            ))
        })?;
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn datagram_socket() -> Result<OwnedFd> {
    // SAFETY: all flags are valid for an unconnected control socket.
    let descriptor =
        unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if descriptor < 0 {
        return Err(attachment_error(format!(
            "failed to open Guest interface control socket: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: the successful socket call returned a uniquely owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

#[cfg(target_os = "linux")]
fn rename_interface(socket: &OwnedFd, from: &str, to: &str) -> Result<()> {
    let mut flags_request = interface_request(from)?;
    // SAFETY: `flags_request` is a writable Linux ifreq and the socket is live.
    if unsafe { libc::ioctl(socket.as_raw_fd(), SIOCGIFFLAGS_REQUEST, &mut flags_request) } < 0 {
        return Err(attachment_error(format!(
            "failed to read Guest interface {from} flags: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: SIOCGIFFLAGS initialized the union's flags member.
    let original_flags = unsafe { flags_request.ifr_ifru.ifru_flags };
    if i32::from(original_flags) & libc::IFF_UP != 0 {
        flags_request.ifr_ifru.ifru_flags = original_flags & !(libc::IFF_UP as i16);
        // SAFETY: `flags_request` contains the exact source name and flags.
        if unsafe { libc::ioctl(socket.as_raw_fd(), SIOCSIFFLAGS_REQUEST, &flags_request) } < 0 {
            return Err(attachment_error(format!(
                "failed to bring Guest interface {from} down for rename: {}",
                std::io::Error::last_os_error()
            )));
        }
    }

    let mut rename_request = interface_request(from)?;
    copy_interface_name(to, unsafe { &mut rename_request.ifr_ifru.ifru_newname })?;
    // SAFETY: both names are validated NUL-terminated ifreq arrays.
    if unsafe { libc::ioctl(socket.as_raw_fd(), SIOCSIFNAME_REQUEST, &rename_request) } < 0 {
        let error = std::io::Error::last_os_error();
        if i32::from(original_flags) & libc::IFF_UP != 0 {
            flags_request.ifr_ifru.ifru_flags = original_flags;
            // SAFETY: best-effort restoration uses the original live name.
            unsafe {
                libc::ioctl(socket.as_raw_fd(), SIOCSIFFLAGS_REQUEST, &flags_request);
            }
        }
        return Err(attachment_error(format!(
            "failed to rename Guest interface {from} to {to}: {error}"
        )));
    }
    if i32::from(original_flags) & libc::IFF_UP != 0 {
        let mut restore = interface_request(to)?;
        restore.ifr_ifru.ifru_flags = original_flags;
        // SAFETY: the renamed interface is addressed by its exact new name.
        if unsafe { libc::ioctl(socket.as_raw_fd(), SIOCSIFFLAGS_REQUEST, &restore) } < 0 {
            return Err(attachment_error(format!(
                "failed to restore Guest interface {to} flags: {}",
                std::io::Error::last_os_error()
            )));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn interface_request(name: &str) -> Result<libc::ifreq> {
    // SAFETY: zero is a valid initial representation for Linux ifreq.
    let mut request = unsafe { std::mem::zeroed::<libc::ifreq>() };
    copy_interface_name(name, &mut request.ifr_name)?;
    Ok(request)
}

#[cfg(target_os = "linux")]
fn copy_interface_name(name: &str, output: &mut [libc::c_char; libc::IFNAMSIZ]) -> Result<()> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() >= libc::IFNAMSIZ || bytes.contains(&0) {
        return Err(attachment_error(format!(
            "invalid Guest interface name {name:?}"
        )));
    }
    output.fill(0);
    for (slot, byte) in output.iter_mut().zip(bytes) {
        *slot = *byte as libc::c_char;
    }
    Ok(())
}
