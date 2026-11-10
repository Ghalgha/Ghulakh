//! Deterministic IPv4 flow hashing for stable multipath scheduling.
//! This hash is for path selection only, never for authentication.
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
    if fragment & 0x1fff != 0 {
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
        packet[2..4].copy_from_slice(&(packet.len() as u16).to_be_bytes());
        packet[9] = proto;
        packet[12..16].copy_from_slice(&src);
        packet[16..20].copy_from_slice(&dst);
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet
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
