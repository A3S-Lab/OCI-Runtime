use super::*;

pub(super) struct NetlinkMessage<'a> {
    pub(super) message_type: u16,
    pub(super) flags: u16,
    pub(super) sequence: u32,
    pub(super) payload: &'a [u8],
}

pub(super) fn parse_netlink_messages(response: &[u8]) -> Result<Vec<NetlinkMessage<'_>>> {
    let mut offset = 0_usize;
    let mut messages = Vec::new();
    while offset < response.len() {
        if response.len() - offset < NETLINK_HEADER_BYTES {
            return Err(netlink_error(
                ErrorCode::FailedPrecondition,
                "route netlink response contains a truncated header",
            ));
        }
        let header = &response[offset..offset + NETLINK_HEADER_BYTES];
        let length = usize::try_from(u32::from_ne_bytes(
            header[0..4].try_into().expect("four-byte slice"),
        ))
        .map_err(|error| {
            netlink_error(
                ErrorCode::FailedPrecondition,
                format!("route netlink message length is invalid: {error}"),
            )
        })?;
        if length < NETLINK_HEADER_BYTES || length > response.len() - offset {
            return Err(netlink_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "route netlink message declares {length} bytes with {} remaining",
                    response.len() - offset
                ),
            ));
        }
        messages.push(NetlinkMessage {
            message_type: u16::from_ne_bytes(header[4..6].try_into().expect("two-byte slice")),
            flags: u16::from_ne_bytes(header[6..8].try_into().expect("two-byte slice")),
            sequence: u32::from_ne_bytes(header[8..12].try_into().expect("four-byte slice")),
            payload: &response[offset + NETLINK_HEADER_BYTES..offset + length],
        });
        offset = offset.checked_add(align4(length)).ok_or_else(|| {
            netlink_error(
                ErrorCode::ResourceExhausted,
                "route netlink message alignment overflow",
            )
        })?;
        if offset > response.len() {
            return Err(netlink_error(
                ErrorCode::FailedPrecondition,
                "route netlink response omits declared message padding",
            ));
        }
    }
    Ok(messages)
}

pub(super) fn parse_acknowledgement(payload: &[u8]) -> Result<()> {
    if payload.len() < 4 {
        return Err(netlink_error(
            ErrorCode::FailedPrecondition,
            format!(
                "route netlink acknowledgement contains {} bytes; expected at least 4",
                payload.len()
            ),
        ));
    }
    let status = i32::from_ne_bytes(payload[0..4].try_into().expect("four-byte slice"));
    if status == 0 {
        return Ok(());
    }
    if status > 0 {
        return Err(netlink_error(
            ErrorCode::FailedPrecondition,
            format!("route netlink acknowledgement returned positive status {status}"),
        ));
    }
    let errno = status.checked_neg().ok_or_else(|| {
        netlink_error(
            ErrorCode::FailedPrecondition,
            "route netlink acknowledgement status underflowed",
        )
    })?;
    Err(io_error(
        "apply route netlink network-device request",
        io::Error::from_raw_os_error(errno),
    ))
}

pub(super) fn dump_request(
    message_type: u16,
    payload_bytes: usize,
    sequence: u32,
) -> Result<Vec<u8>> {
    let length = NETLINK_HEADER_BYTES
        .checked_add(payload_bytes)
        .ok_or_else(|| {
            netlink_error(
                ErrorCode::ResourceExhausted,
                "netlink request size overflow",
            )
        })?;
    let mut request = vec![0_u8; length];
    write_header(
        &mut request,
        message_type,
        NLM_F_REQUEST | NLM_F_DUMP,
        sequence,
    )?;
    request[NETLINK_HEADER_BYTES] = libc::AF_UNSPEC as u8;
    Ok(request)
}

pub(super) fn move_request(
    index: i32,
    target_namespace: RawFd,
    target_name: &str,
    up: bool,
    sequence: u32,
) -> Result<Vec<u8>> {
    if index <= 0 || target_namespace < 0 || target_name.is_empty() {
        return Err(netlink_error(
            ErrorCode::InvalidArgument,
            "network-device move requires a positive interface index, live namespace descriptor, and target name",
        ));
    }
    let mut request = vec![0_u8; NETLINK_HEADER_BYTES + INTERFACE_INFO_BYTES];
    request[NETLINK_HEADER_BYTES] = libc::AF_UNSPEC as u8;
    request[NETLINK_HEADER_BYTES + 4..NETLINK_HEADER_BYTES + 8]
        .copy_from_slice(&index.to_ne_bytes());
    request[NETLINK_HEADER_BYTES + 8..NETLINK_HEADER_BYTES + 12]
        .copy_from_slice(&(u32::from(up) * libc::IFF_UP as u32).to_ne_bytes());
    request[NETLINK_HEADER_BYTES + 12..NETLINK_HEADER_BYTES + 16]
        .copy_from_slice(&(libc::IFF_UP as u32).to_ne_bytes());
    append_attribute(
        &mut request,
        IFLA_NET_NS_FD,
        &target_namespace.to_ne_bytes(),
    )?;
    let mut encoded_name = target_name.as_bytes().to_vec();
    encoded_name.push(0);
    append_attribute(&mut request, IFLA_IFNAME, &encoded_name)?;
    write_header(
        &mut request,
        libc::RTM_NEWLINK,
        NLM_F_REQUEST | NLM_F_ACK,
        sequence,
    )?;
    Ok(request)
}

fn write_header(request: &mut [u8], message_type: u16, flags: u16, sequence: u32) -> Result<()> {
    if request.len() < NETLINK_HEADER_BYTES {
        return Err(netlink_error(
            ErrorCode::Internal,
            "netlink request is shorter than its header",
        ));
    }
    let length = u32::try_from(request.len()).map_err(|error| {
        netlink_error(
            ErrorCode::ResourceExhausted,
            format!("netlink request length does not fit u32: {error}"),
        )
    })?;
    request[0..4].copy_from_slice(&length.to_ne_bytes());
    request[4..6].copy_from_slice(&message_type.to_ne_bytes());
    request[6..8].copy_from_slice(&flags.to_ne_bytes());
    request[8..12].copy_from_slice(&sequence.to_ne_bytes());
    request[12..16].copy_from_slice(&0_u32.to_ne_bytes());
    Ok(())
}

fn append_attribute(request: &mut Vec<u8>, attribute_type: u16, value: &[u8]) -> Result<()> {
    let length = ROUTE_ATTRIBUTE_BYTES
        .checked_add(value.len())
        .ok_or_else(|| {
            netlink_error(
                ErrorCode::ResourceExhausted,
                "route netlink attribute size overflow",
            )
        })?;
    let encoded_length = u16::try_from(length).map_err(|error| {
        netlink_error(
            ErrorCode::ResourceExhausted,
            format!("route netlink attribute length does not fit u16: {error}"),
        )
    })?;
    request.extend_from_slice(&encoded_length.to_ne_bytes());
    request.extend_from_slice(&attribute_type.to_ne_bytes());
    request.extend_from_slice(value);
    request.resize(
        request
            .len()
            .checked_add(align4(length) - length)
            .ok_or_else(|| {
                netlink_error(
                    ErrorCode::ResourceExhausted,
                    "route netlink attribute padding overflow",
                )
            })?,
        0,
    );
    Ok(())
}

pub(super) fn parse_link(payload: &[u8]) -> io::Result<LinkSnapshot> {
    if payload.len() < INTERFACE_INFO_BYTES {
        return Err(invalid_data("network-interface payload is truncated"));
    }
    let link_type = u16::from_ne_bytes(payload[2..4].try_into().expect("two-byte slice"));
    let index = i32::from_ne_bytes(payload[4..8].try_into().expect("four-byte slice"));
    if index <= 0 {
        return Err(invalid_data(format!(
            "network-interface index {index} is not positive"
        )));
    }
    let flags = u32::from_ne_bytes(payload[8..12].try_into().expect("four-byte slice"));
    let attributes = parse_attributes(&payload[INTERFACE_INFO_BYTES..])?;
    let name = attributes
        .get(&IFLA_IFNAME)
        .ok_or_else(|| invalid_data("network-interface response omits IFLA_IFNAME"))?;
    let name = parse_nul_string(name, "network-interface name")?;
    let stable = attributes
        .into_iter()
        .filter(|(kind, _)| STABLE_LINK_ATTRIBUTES.contains(kind) || *kind == IFLA_MASTER)
        .collect();
    Ok(LinkSnapshot {
        index,
        name,
        link_type,
        flags,
        attributes: stable,
        addresses: Vec::new(),
    })
}

pub(super) fn parse_address(payload: &[u8]) -> io::Result<Option<(i32, AddressSnapshot)>> {
    if payload.len() < INTERFACE_ADDRESS_BYTES {
        return Err(invalid_data("network-address payload is truncated"));
    }
    let family = payload[0];
    let prefix_length = payload[1];
    let header_flags = u32::from(payload[2]);
    let scope = payload[3];
    let index_u32 = u32::from_ne_bytes(payload[4..8].try_into().expect("four-byte slice"));
    let index = i32::try_from(index_u32)
        .map_err(|error| invalid_data(format!("network-address index is invalid: {error}")))?;
    if index <= 0 {
        return Err(invalid_data(format!(
            "network-address index {index} is not positive"
        )));
    }
    let attributes = parse_attributes(&payload[INTERFACE_ADDRESS_BYTES..])?;
    let flags = attributes
        .get(&IFA_FLAGS)
        .and_then(|value| value.get(..4))
        .map(|value| u32::from_ne_bytes(value.try_into().expect("four-byte slice")))
        .unwrap_or(header_flags);
    if scope != RT_SCOPE_UNIVERSE || flags & IFA_F_PERMANENT == 0 {
        return Ok(None);
    }
    let stable = attributes
        .into_iter()
        .filter(|(kind, _)| STABLE_ADDRESS_ATTRIBUTES.contains(kind))
        .collect::<BTreeMap<_, _>>();
    if !stable.contains_key(&IFA_ADDRESS) && !stable.contains_key(&IFA_LOCAL) {
        return Err(invalid_data(
            "permanent global network address omits IFA_ADDRESS and IFA_LOCAL",
        ));
    }
    Ok(Some((
        index,
        AddressSnapshot {
            family,
            prefix_length,
            flags: flags & !VOLATILE_ADDRESS_FLAGS,
            attributes: stable,
        },
    )))
}

fn parse_attributes(mut bytes: &[u8]) -> io::Result<BTreeMap<u16, Vec<u8>>> {
    let mut attributes = BTreeMap::new();
    while !bytes.is_empty() {
        if bytes.len() < ROUTE_ATTRIBUTE_BYTES {
            return Err(invalid_data("route attribute header is truncated"));
        }
        let length = usize::from(u16::from_ne_bytes(
            bytes[0..2].try_into().expect("two-byte slice"),
        ));
        if length < ROUTE_ATTRIBUTE_BYTES || length > bytes.len() {
            return Err(invalid_data(format!(
                "route attribute declares {length} bytes with {} remaining",
                bytes.len()
            )));
        }
        let kind = u16::from_ne_bytes(bytes[2..4].try_into().expect("two-byte slice")) & 0x3fff;
        if attributes
            .insert(kind, bytes[ROUTE_ATTRIBUTE_BYTES..length].to_vec())
            .is_some()
        {
            return Err(invalid_data(format!(
                "route response contains duplicate attribute {kind}"
            )));
        }
        let aligned = align4(length);
        if aligned > bytes.len() {
            return Err(invalid_data("route attribute padding is truncated"));
        }
        bytes = &bytes[aligned..];
    }
    Ok(attributes)
}

fn parse_nul_string(value: &[u8], description: &str) -> io::Result<String> {
    let Some(nul) = value.iter().position(|byte| *byte == 0) else {
        return Err(invalid_data(format!("{description} is not NUL-terminated")));
    };
    if nul == 0 || value[nul..].iter().any(|byte| *byte != 0) {
        return Err(invalid_data(format!(
            "{description} is empty or contains bytes after its terminator"
        )));
    }
    String::from_utf8(value[..nul].to_vec())
        .map_err(|error| invalid_data(format!("{description} is not UTF-8: {error}")))
}

const fn align4(length: usize) -> usize {
    length.saturating_add(3) & !3
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::new();
        append_attribute(&mut encoded, kind, value).expect("encode test attribute");
        encoded
    }

    #[test]
    fn move_request_sets_namespace_name_and_only_the_up_flag() {
        let request = move_request(17, 23, "eth%d", true, 9).expect("move request");
        assert_eq!(
            u32::from_ne_bytes(request[0..4].try_into().unwrap()) as usize,
            request.len()
        );
        assert_eq!(
            u16::from_ne_bytes(request[4..6].try_into().unwrap()),
            libc::RTM_NEWLINK
        );
        assert_eq!(i32::from_ne_bytes(request[20..24].try_into().unwrap()), 17);
        assert_eq!(
            u32::from_ne_bytes(request[24..28].try_into().unwrap()),
            libc::IFF_UP as u32
        );
        assert_eq!(
            u32::from_ne_bytes(request[28..32].try_into().unwrap()),
            libc::IFF_UP as u32
        );
        let attributes = parse_attributes(&request[32..]).expect("parse move attributes");
        assert_eq!(
            i32::from_ne_bytes(attributes[&IFLA_NET_NS_FD][..4].try_into().unwrap()),
            23
        );
        assert_eq!(attributes[&IFLA_IFNAME], b"eth%d\0");
    }

    #[test]
    fn parses_link_identity_and_only_permanent_global_addresses() {
        let mut link = vec![0_u8; INTERFACE_INFO_BYTES];
        link[2..4].copy_from_slice(&1_u16.to_ne_bytes());
        link[4..8].copy_from_slice(&17_i32.to_ne_bytes());
        link[8..12].copy_from_slice(&(libc::IFF_UP as u32).to_ne_bytes());
        link.extend(attribute(IFLA_IFNAME, b"eth0\0"));
        link.extend(attribute(IFLA_MTU, &1500_u32.to_ne_bytes()));
        link.extend(attribute(IFLA_QDISC, b"noop\0"));
        let parsed = parse_link(&link).expect("parse link");
        assert_eq!(parsed.index, 17);
        assert_eq!(parsed.name, "eth0");
        assert_eq!(parsed.attributes[&IFLA_MTU], 1500_u32.to_ne_bytes());
        assert!(!parsed.attributes.contains_key(&IFLA_QDISC));

        let mut address = vec![0_u8; INTERFACE_ADDRESS_BYTES];
        address[0] = libc::AF_INET as u8;
        address[1] = 24;
        address[2] = IFA_F_PERMANENT as u8;
        address[3] = RT_SCOPE_UNIVERSE;
        address[4..8].copy_from_slice(&17_u32.to_ne_bytes());
        address.extend(attribute(IFA_LOCAL, &[192, 0, 2, 10]));
        address.extend(attribute(IFA_LABEL, b"eth0\0"));
        address.extend(attribute(
            IFA_FLAGS,
            &(IFA_F_PERMANENT | IFA_F_TENTATIVE).to_ne_bytes(),
        ));
        let (_, parsed_address) = parse_address(&address)
            .expect("parse global address")
            .expect("permanent global address");
        assert!(!parsed_address.attributes.contains_key(&IFA_LABEL));
        assert!(!parsed_address.attributes.contains_key(&IFA_FLAGS));
        assert_eq!(parsed_address.flags, IFA_F_PERMANENT);
        address[3] = 253;
        assert!(parse_address(&address)
            .expect("parse link-local address")
            .is_none());
    }

    #[test]
    fn netlink_frames_reject_truncation_and_preserve_kernel_errno() {
        let mut message = vec![0_u8; NETLINK_ERROR_BYTES];
        write_header(&mut message, NLMSG_ERROR, 0, 7).expect("write error header");
        message[NETLINK_HEADER_BYTES..NETLINK_ERROR_BYTES]
            .copy_from_slice(&(-libc::EEXIST).to_ne_bytes());
        let parsed = parse_netlink_messages(&message).expect("parse netlink error");
        let error = parse_acknowledgement(parsed[0].payload).expect_err("kernel error");
        assert_eq!(error.code, ErrorCode::Conflict);

        message[0..4].copy_from_slice(&((NETLINK_ERROR_BYTES + 1) as u32).to_ne_bytes());
        assert!(parse_netlink_messages(&message).is_err());
    }
}
