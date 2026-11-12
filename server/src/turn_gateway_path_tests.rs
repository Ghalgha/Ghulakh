use super::*;
use ghulakh_protocol::{
    ordered_datagram::SequencedDataDatagram,
    secure_frame::FrameDirection,
};
use tokio::{net::UdpSocket, time::{timeout, Duration}};

const TEST_CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 2);

fn ipv4_fragment(flags_offset: u16, identification: u16, source_port: Option<u16>) -> Vec<u8> {
    let mut packet = vec![0u8; 28];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&28u16.to_be_bytes());
    packet[4..6].copy_from_slice(&identification.to_be_bytes());
    packet[6..8].copy_from_slice(&flags_offset.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[203, 0, 113, 9]);
    packet[16..20].copy_from_slice(&TEST_CLIENT_IP.octets());
    if let Some(port) = source_port {
        packet[20..22].copy_from_slice(&port.to_be_bytes());
        packet[22..24].copy_from_slice(&443u16.to_be_bytes());
        packet[24..26].copy_from_slice(&8u16.to_be_bytes());
    } else {
        packet[20..28].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    }
    packet
}

fn ipv6_fragment(offset_flags: u16, identification: u32) -> Vec<u8> {
    let mut packet = vec![0u8; 56];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&16u16.to_be_bytes());
    packet[6] = 44;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
    packet[24..40].copy_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
    packet[40] = 17;
    packet[42..44].copy_from_slice(&offset_flags.to_be_bytes());
    packet[44..48].copy_from_slice(&identification.to_be_bytes());
    packet[48..56].copy_from_slice(&[0, 1, 0, 2, 0, 8, 0, 0]);
    packet
}

#[test]
fn scheduler_keeps_ipv4_and_ipv6_fragments_on_one_path() {
    let active = [[0x11; 8], [0x22; 8]];
    let start = Instant::now();
    let mut scheduler = DownlinkScheduler::new();

    let first_v4 = ipv4_fragment(0x2000, 0x1234, Some(12_345));
    let later_v4 = ipv4_fragment(0x0001, 0x1234, None);
    let first_path = scheduler.select(&active, TEST_CLIENT_IP, &first_v4, start);
    let later_path = scheduler.select(&active, TEST_CLIENT_IP, &later_v4, start + Duration::from_millis(1));
    assert_eq!(first_path, later_path, "IPv4 fragments must retain flow affinity");

    let client_v6: Ipv6Addr = "fd77:77::2".parse().unwrap();
    let first_v6 = ipv6_fragment(0x0001, 0x1020_3040);
    let later_v6 = ipv6_fragment(0x0008, 0x1020_3040);
    let first_path = scheduler.select(&active, client_v6, &first_v6, start + Duration::from_millis(2));
    let later_path = scheduler.select(&active, client_v6, &later_v6, start + Duration::from_millis(3));
    assert_eq!(first_path, later_path, "IPv6 fragments must retain flow affinity");
}

#[test]
fn scheduler_distributes_independent_ipv6_flows_across_all_paths() {
    let active: Vec<[u8; 8]> = (0..10).map(|index| [index + 1; 8]).collect();
    let client: Ipv6Addr = "fd77:77::2".parse().unwrap();
    let source: Ipv6Addr = "2001:db8::10".parse().unwrap();
    let destination: Ipv6Addr = "fd77:77::2".parse().unwrap();
    let start = Instant::now();
    let mut scheduler = DownlinkScheduler::new();
    let mut per_path = HashMap::<[u8; 8], usize>::new();

    for port in 10_000..11_000u16 {
        let mut packet = vec![0u8; 48];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&8u16.to_be_bytes());
        packet[6] = 17;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&destination.octets());
        packet[40..42].copy_from_slice(&port.to_be_bytes());
        packet[42..44].copy_from_slice(&443u16.to_be_bytes());
        packet[44..46].copy_from_slice(&8u16.to_be_bytes());
        let selected = scheduler.select(
            &active,
            client,
            &packet,
            start + Duration::from_micros(u64::from(port - 10_000)),
        );
        *per_path.entry(selected).or_default() += 1;
    }

    assert_eq!(per_path.len(), active.len(), "IPv6 flows must reach every active path");
}

#[tokio::test]
async fn authenticated_uplink_reordering_is_restored_across_real_path_sessions() {
    let (gateway, mut tun_rx) = TurnGateway::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let relay_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let session_a = [0xa1; 8];
    let session_b = [0xb2; 8];
    let key_a = [0x31; 32];
    let key_b = [0x32; 32];
    let prefix_a = [0x41; 4];
    let prefix_b = [0x42; 4];
    let group = [0x71; 16];

    gateway.register_session_with_path(
        session_a, TEST_CLIENT_IP, relay_a.local_addr().unwrap(),
        FrameOpener::new(key_a, prefix_a, session_a, FrameDirection::ClientToServer),
        FrameSealer::new([0x51; 32], [0x61; 4], session_a, FrameDirection::ServerToClient),
        Some(TurnPathContext { group_id: group, path_id: 0, path_count: 2 }),
    ).await.unwrap();
    gateway.register_session_with_path(
        session_b, TEST_CLIENT_IP, relay_b.local_addr().unwrap(),
        FrameOpener::new(key_b, prefix_b, session_b, FrameDirection::ClientToServer),
        FrameSealer::new([0x52; 32], [0x62; 4], session_b, FrameDirection::ServerToClient),
        Some(TurnPathContext { group_id: group, path_id: 1, path_count: 2 }),
    ).await.unwrap();

    let make_datagram = |marker: u8| {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28u16.to_be_bytes());
        packet[4..6].copy_from_slice(&u16::from(marker).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&TEST_CLIENT_IP.octets());
        packet[16..20].copy_from_slice(&[203, 0, 113, 9]);
        packet[20..22].copy_from_slice(&12_000u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443u16.to_be_bytes());
        packet[24..26].copy_from_slice(&8u16.to_be_bytes());
        DataDatagram { kind: IpPacketKind::Ipv4, packet }
    };
    let packet_zero = make_datagram(0);
    let packet_one = make_datagram(1);

    let mut path_a = FrameSealer::new(key_a, prefix_a, session_a, FrameDirection::ClientToServer);
    let mut path_b = FrameSealer::new(key_b, prefix_b, session_b, FrameDirection::ClientToServer);
    let frame_one = path_b.seal(&SequencedDataDatagram::new(1, packet_one.clone()).encode().unwrap()).unwrap();
    gateway.process_datagram(&frame_one, relay_b.local_addr().unwrap()).await;
    assert!(tun_rx.try_recv().is_err(), "sequence 1 must wait for sequence 0");

    let frame_zero = path_a.seal(&SequencedDataDatagram::new(0, packet_zero.clone()).encode().unwrap()).unwrap();
    gateway.process_datagram(&frame_zero, relay_a.local_addr().unwrap()).await;

    assert_eq!(timeout(Duration::from_secs(1), tun_rx.recv()).await.unwrap().unwrap(), packet_zero);
    assert_eq!(timeout(Duration::from_secs(1), tun_rx.recv()).await.unwrap().unwrap(), packet_one);
    assert_eq!(gateway.stats().accepted, 2);

    assert!(gateway.unregister_session(session_a).await);
    assert!(gateway.unregister_session(session_b).await);
    assert!(gateway.sessions.read().await.is_empty());
    assert!(gateway.clients.read().await.is_empty());
}
