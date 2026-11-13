//! Deterministic IPv4 flow hashing for stable multipath scheduling.
//! Flow identities are for path selection only, never for authentication.

/// Collision-safe identity for an IPv4 flow. Fragmented datagrams use the
/// IPv4 identification field so the first and subsequent fragments stay
/// on the same path; unfragmented TCP/UDP packets use their transport ports.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Ipv4FlowKey {
    source: [u8; 4],
    destination: [u8; 4],
    protocol: u8,
    discriminator: FlowDiscriminator,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
enum FlowDiscriminator {
    Ports { source: u16, destination: u16 },
    Fragment(u16),
    Other,
}

/// Parse a complete IPv4 header into a collision-safe scheduling key.
/// Returns None for truncated or malformed IPv4 headers.
pub fn ipv4_flow_key(packet: &[u8]) -> Option<Ipv4FlowKey> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len {
        return None;
    }

    let protocol = packet[9];
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    let fragmented = fragment & 0x3fff != 0;
    let discriminator = if fragmented {
        FlowDiscriminator::Fragment(u16::from_be_bytes([packet[4], packet[5]]))
    } else if protocol == 6 || protocol == 17 {
        if packet.len() < header_len + 4 {
            return None;
        }
        FlowDiscriminator::Ports {
            source: u16::from_be_bytes([packet[header_len], packet[header_len + 1]]),
            destination: u16::from_be_bytes([packet[header_len + 2], packet[header_len + 3]]),
        }
    } else {
        FlowDiscriminator::Other
    };

    Some(Ipv4FlowKey {
        source: packet[12..16].try_into().ok()?,
        destination: packet[16..20].try_into().ok()?,
        protocol,
        discriminator,
    })
}

/// Collision-safe identity for an IPv6 flow, including fragment identification.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Ipv6FlowKey {
    source: [u8; 16],
    destination: [u8; 16],
    protocol: u8,
    discriminator: Ipv6FlowDiscriminator,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
enum Ipv6FlowDiscriminator {
    Ports { source: u16, destination: u16 },
    Fragment(u32),
    Other,
}

/// Address-family-neutral flow identity used by both TURN path schedulers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum IpFlowKey {
    Ipv4(Ipv4FlowKey),
    Ipv6(Ipv6FlowKey),
}

impl IpFlowKey {
    pub fn protocol(self) -> u8 {
        match self {
            Self::Ipv4(key) => key.protocol,
            Self::Ipv6(key) => key.protocol,
        }
    }
}

/// Parse an IPv6 packet, following supported extension headers to locate TCP/UDP.
/// Fragmented packets use the fragment identification so every fragment stays together.
pub fn ipv6_flow_key(packet: &[u8]) -> Option<Ipv6FlowKey> {
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return None;
    }
    let source = packet[8..24].try_into().ok()?;
    let destination = packet[24..40].try_into().ok()?;
    let mut protocol = packet[6];
    let mut offset = 40usize;

    loop {
        match protocol {
            0 | 43 | 60 | 135 | 139 | 140 => {
                if packet.len() < offset + 2 {
                    return None;
                }
                let next = packet[offset];
                let length = (usize::from(packet[offset + 1]) + 1).checked_mul(8)?;
                if packet.len() < offset + length {
                    return None;
                }
                protocol = next;
                offset += length;
            }
            51 => {
                if packet.len() < offset + 2 {
                    return None;
                }
                let next = packet[offset];
                let length = (usize::from(packet[offset + 1]) + 2).checked_mul(4)?;
                if packet.len() < offset + length {
                    return None;
                }
                protocol = next;
                offset += length;
            }
            44 => {
                if packet.len() < offset + 8 {
                    return None;
                }
                let next = packet[offset];
                let fragment_id =
                    u32::from_be_bytes(packet[offset + 4..offset + 8].try_into().ok()?);
                return Some(Ipv6FlowKey {
                    source,
                    destination,
                    protocol: next,
                    discriminator: Ipv6FlowDiscriminator::Fragment(fragment_id),
                });
            }
            _ => break,
        }
    }

    let discriminator = if protocol == 6 || protocol == 17 {
        if packet.len() < offset + 4 {
            return None;
        }
        Ipv6FlowDiscriminator::Ports {
            source: u16::from_be_bytes([packet[offset], packet[offset + 1]]),
            destination: u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]),
        }
    } else {
        Ipv6FlowDiscriminator::Other
    };
    Some(Ipv6FlowKey {
        source,
        destination,
        protocol,
        discriminator,
    })
}

/// Parse a flow key for either supported IP version.
pub fn ip_flow_key(packet: &[u8]) -> Option<IpFlowKey> {
    match packet.first()? >> 4 {
        4 => ipv4_flow_key(packet).map(IpFlowKey::Ipv4),
        6 => ipv6_flow_key(packet).map(IpFlowKey::Ipv6),
        _ => None,
    }
}

pub fn flow_hash(packet: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let mut feed = |bytes: &[u8]| {
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };

    if packet.len() < 20 || packet[0] >> 4 != 4 {
        feed(packet);
        return hash;
    }

    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len {
        feed(packet);
        return hash;
    }

    feed(&packet[12..20]);
    feed(&[packet[9]]);
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & 0x3fff != 0 {
        feed(&packet[4..6]);
    } else if (packet[9] == 6 || packet[9] == 17) && packet.len() >= header_len + 4 {
        feed(&packet[header_len..header_len + 4]);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4(
        src: [u8; 4],
        dst: [u8; 4],
        proto: u8,
        source_port: u16,
        destination_port: u16,
    ) -> Vec<u8> {
        let mut packet = vec![0u8; 24];
        packet[0] = 0x45;
        let length = packet.len() as u16;
        packet[2..4].copy_from_slice(&length.to_be_bytes());
        packet[9] = proto;
        packet[12..16].copy_from_slice(&src);
        packet[16..20].copy_from_slice(&dst);
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet
    }

    #[test]
    fn flow_keys_distinguish_ports_without_hash_collisions() {
        let first = ipv4([10, 77, 0, 2], [203, 0, 113, 4], 17, 12345, 443);
        let second = ipv4([10, 77, 0, 2], [203, 0, 113, 4], 17, 12346, 443);
        assert_ne!(ipv4_flow_key(&first), ipv4_flow_key(&second));
        assert_eq!(ipv4_flow_key(&first), ipv4_flow_key(&first.clone()));
    }

    #[test]
    fn first_and_later_fragments_share_one_flow_key() {
        let mut first = ipv4([10, 77, 0, 2], [203, 0, 113, 4], 17, 1000, 2000);
        let mut later = first.clone();
        first[4..6].copy_from_slice(&7u16.to_be_bytes());
        later[4..6].copy_from_slice(&7u16.to_be_bytes());
        first[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        later[6..8].copy_from_slice(&0x2001u16.to_be_bytes());
        assert_eq!(ipv4_flow_key(&first), ipv4_flow_key(&later));
        later[4..6].copy_from_slice(&8u16.to_be_bytes());
        assert_ne!(ipv4_flow_key(&first), ipv4_flow_key(&later));
    }

    #[test]
    fn malformed_ipv4_headers_have_no_flow_key() {
        assert_eq!(ipv4_flow_key(&[0x45; 19]), None);
        let mut malformed = ipv4([10, 0, 0, 1], [10, 0, 0, 2], 17, 1, 2);
        malformed[0] = 0x44;
        assert_eq!(ipv4_flow_key(&malformed), None);
    }

    #[test]
    fn same_five_tuple_has_same_hash() {
        let first = ipv4([10, 77, 0, 2], [203, 0, 113, 4], 6, 12345, 443);
        let second = first.clone();
        assert_eq!(flow_hash(&first), flow_hash(&second));
    }

    #[test]
    fn different_transport_ports_separate_flows() {
        let first = ipv4([10, 77, 0, 2], [203, 0, 113, 4], 6, 12345, 443);
        let second = ipv4([10, 77, 0, 2], [203, 0, 113, 4], 6, 12346, 443);
        assert_ne!(flow_hash(&first), flow_hash(&second));
    }

    #[test]
    fn non_initial_fragments_use_identification_instead_of_ports() {
        let mut first = ipv4([10, 77, 0, 2], [203, 0, 113, 4], 17, 1000, 2000);
        let mut second = first.clone();
        first[4..6].copy_from_slice(&7u16.to_be_bytes());
        second[4..6].copy_from_slice(&7u16.to_be_bytes());
        first[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        second[6..8].copy_from_slice(&0x2001u16.to_be_bytes());
        assert_eq!(flow_hash(&first), flow_hash(&second));
    }

    fn ipv6(source_port: u16, destination_port: u16) -> Vec<u8> {
        let mut packet = vec![0u8; 44];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&4u16.to_be_bytes());
        packet[6] = 17;
        packet[8..24].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet[24..40].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        packet[40..42].copy_from_slice(&source_port.to_be_bytes());
        packet[42..44].copy_from_slice(&destination_port.to_be_bytes());
        packet
    }

    #[test]
    fn ipv6_flow_keys_distinguish_transport_ports() {
        let first = ipv6(12345, 443);
        let second = ipv6(12346, 443);
        assert_ne!(ip_flow_key(&first), ip_flow_key(&second));
        assert_eq!(ip_flow_key(&first), ip_flow_key(&first.clone()));
    }

    #[test]
    fn ipv6_fragments_share_identification_based_flow_key() {
        let mut first = vec![0u8; 56];
        first[0] = 0x60;
        first[4..6].copy_from_slice(&16u16.to_be_bytes());
        first[6] = 44;
        first[8..24].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        first[24..40].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        first[40] = 17;
        first[44..48].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        let mut later = first.clone();
        later[42..44].copy_from_slice(&8u16.to_be_bytes());
        assert_eq!(ip_flow_key(&first), ip_flow_key(&later));
        later[44..48].copy_from_slice(&0x1234_5679u32.to_be_bytes());
        assert_ne!(ip_flow_key(&first), ip_flow_key(&later));
    }

    #[test]
    fn ipv6_flow_key_follows_hop_by_hop_extension_header() {
        let mut packet = vec![0u8; 52];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&12u16.to_be_bytes());
        packet[6] = 0;
        packet[40] = 17;
        packet[41] = 0;
        packet[48..50].copy_from_slice(&1000u16.to_be_bytes());
        packet[50..52].copy_from_slice(&443u16.to_be_bytes());
        assert!(matches!(ip_flow_key(&packet), Some(IpFlowKey::Ipv6(_))));
    }

    fn ipv6_with_extension_headers(chain: &[(u8, Vec<u8>)], transport: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60;
        packet[8..24].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet[24..40].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        packet[6] = chain.first().map_or(17, |(kind, _)| *kind);
        for (index, (kind, mut header)) in chain.iter().cloned().enumerate() {
            let next = chain.get(index + 1).map_or(17, |(next, _)| *next);
            header[0] = next;
            match kind {
                0 | 43 | 60 => header[1] = (header.len() / 8 - 1) as u8,
                51 => header[1] = (header.len() / 4 - 2) as u8,
                _ => {}
            }
            packet.extend_from_slice(&header);
        }
        packet.extend_from_slice(transport);
        let payload_len = (packet.len() - 40) as u16;
        packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
        packet
    }

    #[test]
    fn ipv6_flow_key_walks_routing_and_destination_options_headers() {
        let transport = [0x04, 0xd2, 0x01, 0xbb];
        let routing = vec![0, 0, 0, 0, 0, 0, 0, 0];
        let destination = vec![0, 0, 0, 0, 0, 0, 0, 0];
        let packet = ipv6_with_extension_headers(&[(43, routing), (60, destination)], &transport);
        let Some(IpFlowKey::Ipv6(key)) = ip_flow_key(&packet) else {
            panic!("IPv6 flow key was not parsed");
        };
        assert_eq!(key.protocol, 17);
        assert_eq!(
            key.discriminator,
            Ipv6FlowDiscriminator::Ports {
                source: 1234,
                destination: 443,
            }
        );
    }

    #[test]
    fn ipv6_flow_key_walks_authentication_header() {
        let authentication = vec![0, 0, 0, 0, 0, 0, 0, 0];
        let packet =
            ipv6_with_extension_headers(&[(51, authentication)], &[0x00, 0x35, 0x01, 0xbb]);
        let Some(IpFlowKey::Ipv6(key)) = ip_flow_key(&packet) else {
            panic!("IPv6 AH flow key was not parsed");
        };
        assert_eq!(key.protocol, 17);
        assert_eq!(
            key.discriminator,
            Ipv6FlowDiscriminator::Ports {
                source: 53,
                destination: 443,
            }
        );
    }

    #[test]
    fn ipv6_fragment_key_is_stable_for_first_and_later_fragments() {
        let mut first = ipv6_with_extension_headers(&[(44, vec![0; 8])], &[0, 1, 0, 2]);
        first[40] = 17;
        first[42..44].copy_from_slice(&0x1234u16.to_be_bytes());
        first[44..48].copy_from_slice(&0x1020_3040u32.to_be_bytes());
        let mut later = first.clone();
        later[42..44].copy_from_slice(&8u16.to_be_bytes());
        assert_eq!(ip_flow_key(&first), ip_flow_key(&later));
        later[44..48].copy_from_slice(&0x1020_3041u32.to_be_bytes());
        assert_ne!(ip_flow_key(&first), ip_flow_key(&later));
    }

    #[test]
    fn truncated_ipv6_extension_headers_are_rejected() {
        let mut packet = vec![0u8; 42];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&2u16.to_be_bytes());
        packet[6] = 0;
        packet[40] = 17;
        packet[41] = 1;
        assert_eq!(ipv6_flow_key(&packet), None);
    }
}
