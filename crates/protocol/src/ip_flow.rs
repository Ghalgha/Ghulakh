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

    fn ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, source_port: u16, destination_port: u16) -> Vec<u8> {
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
}
