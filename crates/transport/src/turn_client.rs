//! High-level TURN client session assembly.
//!
//! This composes the protected UDP socket, TURN allocation/authentication,
//! peer permission, channel binding, authenticated Noise handshake and bounded
//! bidirectional IP dataplane. VK API credential acquisition remains external.

use std::{
    net::{SocketAddr, UdpSocket as StdUdpSocket},
};

use anyhow::{Context, Result};
use ghulakh_protocol::{DataDatagram, turn_path_context::TurnPathContext};
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
};

use crate::{
    turn_auth::VkCallsTurnAuthProvider,
    turn_data::{TurnDataReceiver, TurnDataSender},
    turn_dataplane::{TurnDataPlane, TurnDataPlaneStats},
    turn_driver::TurnClientDriver,
    turn_handshake_task::{
        run_turn_client_handshake, run_turn_client_handshake_with_path_context, TurnClientSession,
    },
    turn_supervisor::TurnSessionSupervisor,
    turn_udp::TurnUdpSocket,
    turn_credentials::{TurnCredentials, TurnScheme, TurnWireTransport},
};

pub const DEFAULT_TURN_CHANNEL: u16 = 0x4001;
const APP_QUEUE_CAPACITY: usize = 128;

/// Fully assembled client-side TURN VPN dataplane.
pub struct TurnClientRuntime {
    config: ghulakh_protocol::session_handshake::TurnSessionConfig,
    path_context: Option<TurnPathContext>,
    uplink: mpsc::Sender<DataDatagram>,
    downlink: tokio::sync::Mutex<mpsc::Receiver<DataDatagram>>,
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
        Self::connect_inner(
            protected_socket, credentials, gateway_peer, pinned_server_key, tunnel_credential, None,
        ).await
    }

    pub async fn connect_with_path_context(
        protected_socket: StdUdpSocket,
        credentials: TurnCredentials,
        gateway_peer: SocketAddr,
        pinned_server_key: &[u8],
        tunnel_credential: &[u8],
        path_context: TurnPathContext,
    ) -> Result<Self> {
        Self::connect_inner(
            protected_socket,
            credentials,
            gateway_peer,
            pinned_server_key,
            tunnel_credential,
            Some(path_context),
        ).await
    }

    async fn connect_inner(
        protected_socket: StdUdpSocket,
        credentials: TurnCredentials,
        gateway_peer: SocketAddr,
        pinned_server_key: &[u8],
        tunnel_credential: &[u8],
        path_context: Option<TurnPathContext>,
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
            endpoint.scheme == TurnScheme::Turn && endpoint.transport == TurnWireTransport::Udp,
            "only plain UDP TURN URIs are currently supported"
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
        let handshake = match path_context {
            Some(context) => run_turn_client_handshake_with_path_context(
                handshake_socket,
                handshake_inbound,
                relay_endpoint,
                DEFAULT_TURN_CHANNEL,
                pinned_server_key,
                tunnel_credential,
                context,
            ).await,
            None => run_turn_client_handshake(
                handshake_socket,
                handshake_inbound,
                relay_endpoint,
                DEFAULT_TURN_CHANNEL,
                pinned_server_key,
                tunnel_credential,
            ).await,
        };
        let TurnClientSession { frame_keys, config } =
            handshake.context("authenticate VPN session over TURN")?;

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
        let (maintenance_stopped_tx, mut maintenance_stopped_rx) = watch::channel(false);
        let maintenance_task = tokio::spawn(async move {
            let result = supervisor.maintain_allocation().await;
            let _ = maintenance_stopped_tx.send(true);
            result
        });
        let dataplane_task = tokio::spawn(async move {
            tokio::select! {
                result = plane.run(uplink_rx, downlink_tx) => result,
                _ = maintenance_stopped_rx.changed() => {
                    anyhow::bail!("TURN allocation maintenance stopped")
                }
            }
        });

        Ok(Self {
            config,
            path_context,
            uplink,
            downlink: tokio::sync::Mutex::new(downlink),
            dataplane_task,
            maintenance_task,
        })
    }

    pub fn config(&self) -> ghulakh_protocol::session_handshake::TurnSessionConfig {
        self.config
    }

    pub fn path_context(&self) -> Option<TurnPathContext> {
        self.path_context
    }

    pub async fn send_packet(&self, packet: DataDatagram) -> Result<()> {
        self.uplink.send(packet).await.context("TURN VPN uplink queue closed")
    }

    pub async fn receive_packet(&self) -> Result<DataDatagram> {
        self.downlink.lock().await.recv().await.context("TURN VPN downlink queue closed")
    }

    pub fn dataplane_finished(&self) -> bool {
        self.dataplane_task.is_finished() || self.maintenance_task.is_finished()
    }

    pub fn close(&self) {
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
