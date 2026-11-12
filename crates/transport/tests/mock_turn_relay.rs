//! Test-only UDP TURN relay emulator for the single-allocation client path.
//! Authentication is intentionally omitted: this emulator validates protocol
//! state and forwarding behavior, not VK credential interoperability.

use ghulakh_protocol::{
    stun::{
        decode_xor_address, encode_xor_address, StunAttribute, StunClass, StunMessage,
        ATTR_CHANNEL_NUMBER, ATTR_LIFETIME, ATTR_REQUESTED_TRANSPORT,
        ATTR_XOR_PEER_ADDRESS, ATTR_XOR_RELAYED_ADDRESS, METHOD_ALLOCATE,
        METHOD_CHANNEL_BIND, METHOD_CREATE_PERMISSION, METHOD_REFRESH,
    },
    turn_channel_data::{decode_channel_data, encode_channel_data},
    turn_request::{allocate_request, channel_bind_request, create_permission_request,
        parse_success_response, refresh_request, TurnSuccess},
};
use std::{collections::{HashMap, HashSet}, net::SocketAddr};
use tokio::{net::UdpSocket, time::{timeout, Duration}};

const CHANNEL: u16 = 0x4001;
const LIFETIME: u32 = 600;
const RELAYED: &str = "198.51.100.10:55000";

struct Allocation {
    client: SocketAddr,
    relayed: SocketAddr,
    expires: bool,
    permissions: HashSet<std::net::IpAddr>,
    channels: HashMap<u16, SocketAddr>,
}

impl Allocation {
    fn new(client: SocketAddr, relayed: SocketAddr) -> Self {
        Self { client, relayed, expires: false, permissions: HashSet::new(), channels: HashMap::new() }
    }

    fn handle_control(&mut self, request: StunMessage) -> Result<StunMessage, String> {
        if request.class != StunClass::Request {
            return Err("only STUN requests are accepted".into());
        }
        let mut attributes = Vec::new();
        match request.method {
            METHOD_ALLOCATE => {
                if request.attribute(ATTR_REQUESTED_TRANSPORT) != Some(&[17, 0, 0, 0][..]) {
                    return Err("only UDP Allocate is supported".into());
                }
                attributes.push(StunAttribute {
                    kind: ATTR_XOR_RELAYED_ADDRESS,
                    value: encode_xor_address(self.relayed, &request.transaction_id),
                });
                attributes.push(StunAttribute { kind: ATTR_LIFETIME, value: LIFETIME.to_be_bytes().to_vec() });
            }
            METHOD_CREATE_PERMISSION => {
                let peers: Vec<_> = request.attributes.iter()
                    .filter(|a| a.kind == ATTR_XOR_PEER_ADDRESS)
                    .map(|a| decode_xor_address(&a.value, &request.transaction_id).map_err(|e| e.to_string()))
                    .collect::<Result<_, _>>()?;
                if peers.is_empty() { return Err("CreatePermission has no peers".into()); }
                for peer in peers { self.permissions.insert(peer.ip()); }
            }
            METHOD_CHANNEL_BIND => {
                let channel = request.attribute(ATTR_CHANNEL_NUMBER).ok_or("missing CHANNEL-NUMBER")?;
                if channel.len() != 4 || channel[2..] != [0, 0] { return Err("invalid CHANNEL-NUMBER".into()); }
                let number = u16::from_be_bytes([channel[0], channel[1]]);
                let peer = request.attribute(ATTR_XOR_PEER_ADDRESS).ok_or("missing XOR-PEER-ADDRESS")?;
                let peer = decode_xor_address(peer, &request.transaction_id).map_err(|e| e.to_string())?;
                if !self.permissions.contains(&peer.ip()) { return Err("permission required before ChannelBind".into()); }
                self.channels.insert(number, peer);
            }
            METHOD_REFRESH => {
                let lifetime = request.attribute(ATTR_LIFETIME).ok_or("missing LIFETIME")?;
                if lifetime.len() != 4 { return Err("invalid LIFETIME".into()); }
                let seconds = u32::from_be_bytes(lifetime.try_into().unwrap());
                self.expires = seconds == 0;
                attributes.push(StunAttribute { kind: ATTR_LIFETIME, value: seconds.to_be_bytes().to_vec() });
            }
            _ => return Err("unsupported TURN method".into()),
        }
        Ok(StunMessage {
            method: request.method,
            class: StunClass::SuccessResponse,
            transaction_id: request.transaction_id,
            attributes,
        })
    }

    fn forward_channel_data(&self, input: &[u8]) -> Result<(SocketAddr, Vec<u8>), String> {
        let frame = decode_channel_data(input).map_err(|e| e.to_string())?;
        let peer = self.channels.get(&frame.channel_number).ok_or("unknown channel")?;
        if !self.permissions.contains(&peer.ip()) { return Err("permission expired".into()); }
        Ok((*peer, frame.data.to_vec()))
    }

    fn forward_peer_data(&self, peer: SocketAddr, payload: &[u8]) -> Result<(SocketAddr, Vec<u8>), String> {
        let channel = self.channels.iter().find(|(_, bound)| **bound == peer)
            .map(|(number, _)| *number).ok_or("peer has no channel binding")?;
        if !self.permissions.contains(&peer.ip()) { return Err("permission expired".into()); }
        let packet = encode_channel_data(channel, payload).map_err(|e| e.to_string())?;
        Ok((self.client, packet))
    }
}

#[tokio::test]
async fn control_plane_and_bidirectional_channel_data_work_end_to_end() {
    let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay.local_addr().unwrap();
    let gateway = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let gateway_addr = gateway.local_addr().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();

    let mut allocation = Allocation::new(client_addr, RELAYED.parse().unwrap());
    let relay_task = tokio::spawn(async move {
        let mut buffer = vec![0u8; 2048];
        for _ in 0..6 {
            let (length, source) = timeout(Duration::from_secs(3), relay.recv_from(&mut buffer)).await.unwrap().unwrap();
            if source == client_addr {
                if buffer[0] & 0xc0 == 0x40 {
                    let (peer, payload) = allocation.forward_channel_data(&buffer[..length]).unwrap();
                    relay.send_to(&payload, peer).await.unwrap();
                } else {
                    let request = StunMessage::decode(&buffer[..length]).unwrap();
                    let response = allocation.handle_control(request).unwrap().encode().unwrap();
                    relay.send_to(&response, source).await.unwrap();
                }
            } else {
                let (destination, response) = allocation.forward_peer_data(source, &buffer[..length]).unwrap();
                relay.send_to(&response, destination).await.unwrap();
            }
        }
        allocation
    });

    let mut id = [1u8; 12];
    let allocate = allocate_request(id);
    client.send_to(&allocate.encode().unwrap(), relay_addr).await.unwrap();
    let mut buffer = vec![0u8; 2048];
    let (length, source) = timeout(Duration::from_secs(2), client.recv_from(&mut buffer)).await.unwrap().unwrap();
    assert_eq!(source, relay_addr);
    let response = StunMessage::decode(&buffer[..length]).unwrap();
    assert!(matches!(parse_success_response(&response, METHOD_ALLOCATE).unwrap(),
        TurnSuccess::Allocate { lifetime_seconds: LIFETIME, .. }));

    id[0] = 2;
    let permission = create_permission_request(id, &[gateway_addr]).unwrap();
    client.send_to(&permission.encode().unwrap(), relay_addr).await.unwrap();
    let (length, _) = timeout(Duration::from_secs(2), client.recv_from(&mut buffer)).await.unwrap().unwrap();
    assert_eq!(StunMessage::decode(&buffer[..length]).unwrap().class, StunClass::SuccessResponse);

    id[0] = 3;
    let bind = channel_bind_request(id, CHANNEL, gateway_addr).unwrap();
    client.send_to(&bind.encode().unwrap(), relay_addr).await.unwrap();
    let (length, _) = timeout(Duration::from_secs(2), client.recv_from(&mut buffer)).await.unwrap().unwrap();
    assert_eq!(StunMessage::decode(&buffer[..length]).unwrap().method, METHOD_CHANNEL_BIND);

    let uplink = encode_channel_data(CHANNEL, b"authenticated-uplink-frame").unwrap();
    client.send_to(&uplink, relay_addr).await.unwrap();
    let (length, source) = timeout(Duration::from_secs(2), gateway.recv_from(&mut buffer)).await.unwrap().unwrap();
    assert_eq!(source, relay_addr);
    assert_eq!(&buffer[..length], b"authenticated-uplink-frame");

    gateway.send_to(b"authenticated-downlink-frame", relay_addr).await.unwrap();
    let (length, source) = timeout(Duration::from_secs(2), client.recv_from(&mut buffer)).await.unwrap().unwrap();
    assert_eq!(source, relay_addr);
    let downlink = decode_channel_data(&buffer[..length]).unwrap();
    assert_eq!(downlink.channel_number, CHANNEL);
    assert_eq!(downlink.data, b"authenticated-downlink-frame");

    let final_id = [4u8; 12];
    let refresh = refresh_request(final_id, 0);
    client.send_to(&refresh.encode().unwrap(), relay_addr).await.unwrap();
    let (length, _) = timeout(Duration::from_secs(2), client.recv_from(&mut buffer)).await.unwrap().unwrap();
    let response = StunMessage::decode(&buffer[..length]).unwrap();
    assert!(matches!(parse_success_response(&response, METHOD_REFRESH).unwrap(),
        TurnSuccess::Refresh { lifetime_seconds: 0 }));
    let state = relay_task.await.unwrap();
    assert!(state.expires);
    assert_eq!(state.relayed, RELAYED.parse().unwrap());
}
