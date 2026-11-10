//! High-level TURN client session assembly.
//!
//! This composes the protected UDP socket, TURN allocation/authentication,
//! peer permission, channel binding, authenticated Noise handshake and bounded
//! bidirectional IP dataplane. VK API credential acquisition remains external.

use std::{
    net::{SocketAddr, UdpSocket as StdUdpSocket},
    time::Duration,
};

use anyhow::{Context, Result};
use ghulakh_protocol::DataDatagram;
use tokio::{
    sync::mpsc,
    task::JoinHandle,
};

use crate::{
    turn_auth::VkCallsTurnAuthProvider,
    turn_data::{TurnDataReceiver, TurnDataSender},
    turn_dataplane::{TurnDataPlane, TurnDataPlaneStats},
    turn_driver::TurnClientDriver,
    turn_handshake_task::{run_turn_client_handshake, TurnClientSession},
    turn_socket_actor::TurnInbound,
    turn_supervisor::TurnSessionSupervisor,
    turn_udp::TurnUdpSocket,
    turn_credentials::{TurnCredentials, TurnWireTransport},
};

pub const DEFAULT_TURN_CHANNEL: u16 = 0x4001;
const APP_QUEUE_CAPACITY: usize = 128;

/// Fully assembled client-side TURN VPN dataplane.
pub struct TurnClientRuntime {
    config: ghulakh_protocol::session_handshake::TurnSessionConfig,
    uplink: mpsc::Sender<DataDatagram>,
    downlink: mpsc::Receiver<DataDatagram>,
    dataplane_task: JoinHandle<Result<TurnDataPlaneStats>>,
    maintenance_task: JoinHandle<Result<()>>,
}

impl TurnClientRuntime {
    /// Establish a TURN allocation through a socket already protected by
    /// Android VpnService.protect(fd), authenticate the server with its pinned
    /// Noise static key, then start the bounded IP dataplane.
    pub async fn connect(
        protected_socket: StdUdpSocket,
        credentials: TurnCredentials,
        gateway_peer: SocketAddr,
        pinned_server_key: &[u8],
        tunnel_credential: &[u8],
    ) -> Result<Self> {
        anyhow::ensure!(gateway_peer.port() != 0, "TURN gateway peer port is zero");
        anyhow::ensure!(pinned_server_key.len() == 32, "pinned Noise server key must be 32 bytes");
        anyhow::ensure!(
            !tunnel_credential.is_empty()
                && tunnel_credential.len() <= ghulakh_protocol::MAX_CREDENTIAL_LEN,
            "tunnel credential length is invalid"
        );

        let local_address = protected_socket.local_addr()
            .context("read protected TURN socket address")?;
        let endpoint = credentials.first_udp_endpoint()
            .context("VK Calls response has no UDP TURN endpoint")?
            .clone();
        anyhow::ensure!(
            endpoint.transport == TurnWireTransport::Udp,
            "only UDP TURN transport is currently supported"
        );
        let mut addresses = tokio::net::lookup_host((endpoint.host.as_str(), endpoint.port))
            .await
            .context("resolve VK Calls TURN endpoint")?;
        let relay_endpoint = addresses
            .find(|address| address.is_ipv4() == local_address.is_ipv4())
            .context("TURN endpoint has no address matching the protected socket family")?;

        let socket = TurnUdpSocket::from_protected_socket(protected_socket, relay_endpoint)
            .context("adopt protected VK Calls TURN socket")?;
        let driver = TurnClientDriver::new(socket);
        let provider = VkCallsTurnAuthProvider::from_credentials(credentials)
            .context("initialize VK Calls TURN authentication provider")?;
        let mut supervisor = TurnSessionSupervisor::new(driver, provider);

        supervisor.allocate().await.context("create VK Calls TURN allocation")?;
        supervisor.create_permission(&[gateway_peer]).await
            .context("create TURN permission for VPN gateway")?;
        supervisor.channel_bind(DEFAULT_TURN_CHANNEL, gateway_peer).await
            .context("bind TURN channel to VPN gateway")?;

        let relay_endpoint = supervisor.relay_endpoint();
        let (handshake_socket, handshake_inbound) = supervisor
            .take_handshake_plane_parts()
            .context("take isolated TURN handshake queue")?;
        let TurnClientSession { frame_keys, config } = run_turn_client_handshake(
            handshake_socket,
            handshake_inbound,
            relay_endpoint,
            DEFAULT_TURN_CHANNEL,
            pinned_server_key,
            tunnel_credential,
        ).await.context("authenticate VPN session over TURN")?;

        let (data_socket, data_inbound) = supervisor
            .take_data_plane_parts()
            .context("take TURN dataplane queue")?;
        let (uplink_sealer, downlink_opener) = frame_keys.into_client_codecs();
        let plane = TurnDataPlane::new(
            data_socket,
            data_inbound,
            relay_endpoint,
            TurnDataSender::new(DEFAULT_TURN_CHANNEL, uplink_sealer),
            TurnDataReceiver::new(DEFAULT_TURN_CHANNEL, downlink_opener),
        );
        let (uplink, uplink_rx) = mpsc::channel(APP_QUEUE_CAPACITY);
        let (downlink_tx, downlink) = mpsc::channel(APP_QUEUE_CAPACITY);
        let dataplane_task = tokio::spawn(plane.run(uplink_rx, downlink_tx));
        let maintenance_task = tokio::spawn(supervisor.maintain_allocation());

        Ok(Self {
            config,
            uplink,
            downlink,
            dataplane_task,
            maintenance_task,
        })
    }

    pub fn config(&self) -> ghulakh_protocol::session_handshake::TurnSessionConfig {
        self.config
    }

    pub async fn send_packet(&self, packet: DataDatagram) -> Result<()> {
        self.uplink.send(packet).await.context("TURN VPN uplink queue closed")
    }

    pub async fn receive_packet(&mut self) -> Result<DataDatagram> {
        self.downlink.recv().await.context("TURN VPN downlink queue closed")
    }

    pub fn dataplane_finished(&self) -> bool {
        self.dataplane_task.is_finished() || self.maintenance_task.is_finished()
    }

    pub fn close(&mut self) {
        self.dataplane_task.abort();
        self.maintenance_task.abort();
    }
}

impl Drop for TurnClientRuntime {
    fn drop(&mut self) {
        self.dataplane_task.abort();
        self.maintenance_task.abort();
    }
}
