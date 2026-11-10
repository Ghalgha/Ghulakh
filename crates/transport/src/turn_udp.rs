//! UDP socket I/O for the VK Calls TURN client transport.
//!
//! Android callers may supply a socket protected from the VPN route through
//! VpnService.protect(). This module never creates a fallback network transport.

use anyhow::{ensure, Context, Result};
use ghulakh_protocol::{
    encode_channel_data, StunMessage, CHANNEL_DATA_HEADER_LEN, MAX_UDP_CHANNEL_DATA_PAYLOAD,
};
use std::net::{SocketAddr, UdpSocket as StdUdpSocket};
use tokio::net::UdpSocket;

pub const MAX_UDP_DATAGRAM_SIZE: usize = 65_507;

pub struct TurnUdpSocket {
    socket: UdpSocket,
    server: SocketAddr,
}

impl TurnUdpSocket {
    /// Bind a new UDP socket. On Android, prefer from_protected_socket so the
    /// caller can protect the descriptor before it is attached to the VPN.
    pub async fn bind(local: SocketAddr, server: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(local).await.context("bind TURN UDP socket")?;
        Ok(Self { socket, server })
    }

    /// Adopt an already-bound std UDP socket, typically after Android
    /// VpnService.protect(fd) has excluded it from the VPN's own routing.
    /// Must be called while a Tokio I/O runtime is active.
    pub fn from_protected_socket(socket: StdUdpSocket, server: SocketAddr) -> Result<Self> {
        socket.set_nonblocking(true).context("set protected TURN socket nonblocking")?;
        let socket = UdpSocket::from_std(socket).context("adopt protected TURN UDP socket")?;
        Ok(Self { socket, server })
    }

    pub fn server_addr(&self) -> SocketAddr {
        self.server
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket.local_addr().context("read TURN socket local address")
    }

    /// Send one raw STUN/TURN control datagram to the configured endpoint.
    pub async fn send_control(&self, message: &StunMessage) -> Result<usize> {
        let encoded = message.encode().context("encode STUN/TURN message")?;
        self.send_datagram(&encoded).await
    }

    /// Send one application frame using the negotiated TURN channel binding.
    pub async fn send_channel_data(&self, channel_number: u16, frame: &[u8]) -> Result<usize> {
        ensure!(
            frame.len() <= MAX_UDP_CHANNEL_DATA_PAYLOAD,
            "TURN ChannelData payload exceeds UDP limit"
        );
        let encoded = encode_channel_data(channel_number, frame)
            .context("encode TURN ChannelData")?;
        self.send_datagram(&encoded).await
    }

    /// Send one complete UDP datagram to the configured TURN endpoint.
    pub async fn send_datagram(&self, datagram: &[u8]) -> Result<usize> {
        ensure!(
            datagram.len() <= MAX_UDP_DATAGRAM_SIZE,
            "TURN UDP datagram exceeds maximum size"
        );
        let sent = self.socket.send_to(datagram, self.server).await
            .context("send datagram to TURN endpoint")?;
        ensure!(sent == datagram.len(), "partial UDP datagram send");
        Ok(sent)
    }

    /// Receive one UDP datagram and preserve its source address. The caller
    /// must match STUN transactions against this exact source endpoint.
    pub async fn receive_datagram(&self, buffer: &mut [u8]) -> Result<(usize, SocketAddr)> {
        ensure!(
            buffer.len() >= MAX_UDP_DATAGRAM_SIZE,
            "TURN receive buffer must hold a maximum-sized UDP datagram"
        );
        self.socket.recv_from(buffer).await.context("receive TURN UDP datagram")
    }

    pub fn minimum_channel_data_buffer() -> usize {
        CHANNEL_DATA_HEADER_LEN + MAX_UDP_CHANNEL_DATA_PAYLOAD
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn exchanges_datagrams_with_exact_turn_endpoint() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = TurnUdpSocket::bind("127.0.0.1:0".parse().unwrap(), server_addr)
            .await.unwrap();

        let payload = b"turn-control-test";
        assert_eq!(client.send_datagram(payload).await.unwrap(), payload.len());

        let mut server_buffer = [0u8; 128];
        let (received, client_addr) = server.recv_from(&mut server_buffer).await.unwrap();
        assert_eq!(&server_buffer[..received], payload);

        server.send_to(b"reply", client_addr).await.unwrap();
        let mut receive_buffer = vec![0u8; MAX_UDP_DATAGRAM_SIZE];
        let (received, source) = client.receive_datagram(&mut receive_buffer).await.unwrap();
        assert_eq!(&receive_buffer[..received], b"reply");
        assert_eq!(source, server_addr);
    }

    #[tokio::test]
    async fn sends_channel_data_to_turn_endpoint() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = TurnUdpSocket::bind("127.0.0.1:0".parse().unwrap(), server_addr)
            .await.unwrap();

        client.send_channel_data(0x4001, b"frame").await.unwrap();
        let mut buffer = [0u8; 64];
        let (length, _) = server.recv_from(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..length], &[0x40, 0x01, 0, 5, b'f', b'r', b'a', b'm', b'e']);
    }

    #[tokio::test]
    async fn adopts_prebound_socket() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let std_socket = StdUdpSocket::bind("127.0.0.1:0").unwrap();
        let client = TurnUdpSocket::from_protected_socket(std_socket, server_addr).unwrap();
        assert_ne!(client.local_addr().unwrap().port(), 0);
    }
}
