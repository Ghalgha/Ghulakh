//! High-level TURN client session assembly.
//!
//! This composes the protected UDP socket, TURN allocation/authentication,
//! peer permission, channel binding, authenticated Noise handshake and bounded
//! bidirectional IP dataplane. VK API credential acquisition remains external.

use std::{
    net::{SocketAddr, UdpSocket as StdUdpSocket},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, RwLock, Mutex as StdMutex,
    },
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


/// One logical VPN tunnel backed by several independent authenticated TURN paths.
/// Flow affinity keeps each IP flow on one path while preserving aggregate
/// throughput across concurrent flows and avoiding packet reordering.
pub struct TurnClientPathGroup {
    config: ghulakh_protocol::session_handshake::TurnSessionConfig,
    paths: RwLock<Vec<Arc<TurnClientRuntime>>>,
    healthy: Vec<Arc<AtomicBool>>,
    downlink: tokio::sync::Mutex<mpsc::Receiver<DataDatagram>>,
    downlink_senders: StdMutex<mpsc::Sender<DataDatagram>>,
    forwarders: StdMutex<Vec<JoinHandle<()>>>,
    uplink_queue_drops: AtomicU64,
}

impl TurnClientPathGroup {
    pub fn new(mut paths: Vec<TurnClientRuntime>) -> Result<Self> {
        anyhow::ensure!(
            (2..=usize::from(ghulakh_protocol::turn_path_context::MAX_TURN_PATHS))
                .contains(&paths.len()),
            "TURN path group must contain 2 to 10 paths"
        );
        let config = paths[0].config();
        let first_context = paths[0].path_context()
            .context("TURN path group contains a path without authenticated path context")?;
        let mut seen = std::collections::HashSet::new();
        for path in &paths {
            anyhow::ensure!(path.config() == config, "TURN paths disagree on tunnel IPv4 or MTU");
            let context = path.path_context()
                .context("TURN path group contains a path without authenticated path context")?;
            context.validate().context("validate TURN path group member")?;
            anyhow::ensure!(
                context.group_id == first_context.group_id
                    && context.path_count == first_context.path_count,
                "TURN path group members have inconsistent group metadata"
            );
            anyhow::ensure!(seen.insert(context.path_id), "duplicate TURN path identifier");
        }
        anyhow::ensure!(
            paths.len() <= usize::from(first_context.path_count),
            "connected TURN path count exceeds the authenticated group size"
        );
        paths.sort_by_key(|path| path.path_context().map(|context| context.path_id).unwrap_or(u16::MAX));

        let paths: Vec<Arc<TurnClientRuntime>> = paths.into_iter().map(Arc::new).collect();
        let healthy: Vec<Arc<AtomicBool>> = paths.iter()
            .map(|_| Arc::new(AtomicBool::new(true)))
            .collect();
        let (downlink_tx, downlink) = mpsc::channel(APP_QUEUE_CAPACITY * 2);
        let mut forwarders = Vec::with_capacity(paths.len());

        for (path, path_health) in paths.iter().cloned().zip(healthy.iter().cloned()) {
            let sender = downlink_tx.clone();
            forwarders.push(tokio::spawn(async move {
                while let Ok(packet) = path.receive_packet().await {
                    if sender.send(packet).await.is_err() {
                        break;
                    }
                }
                path_health.store(false, Ordering::Release);
            }));
        }
        let downlink_tx_for_group = downlink_tx.clone();
        drop(downlink_tx);

        Ok(Self {
            config,
            paths: RwLock::new(paths),
            healthy,
            downlink: tokio::sync::Mutex::new(downlink),
            downlink_senders: StdMutex::new(downlink_tx_for_group),
            forwarders: StdMutex::new(forwarders),
            uplink_queue_drops: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> ghulakh_protocol::session_handshake::TurnSessionConfig {
        self.config
    }

    pub fn active_paths(&self) -> usize {
        self.healthy.iter().filter(|path| path.load(Ordering::Acquire)).count()
    }

    /// Atomically replace one failed path after a fresh authenticated TURN handshake.
    pub fn replace_path(&self, replacement: TurnClientRuntime) -> Result<()> {
        anyhow::ensure!(replacement.config() == self.config, "replacement TURN path changed tunnel IPv4 or MTU");
        let context = replacement.path_context()
            .context("replacement TURN path has no authenticated path context")?;
        context.validate().context("validate replacement TURN path context")?;
        let mut paths = self.paths.write()
            .map_err(|_| anyhow::anyhow!("TURN path registry is poisoned"))?;
        let first = paths.first().context("TURN path group is empty")?
            .path_context().context("existing TURN path has no path context")?;
        anyhow::ensure!(
            context.group_id == first.group_id && context.path_count == first.path_count,
            "replacement TURN path belongs to a different tunnel group"
        );
        let index = paths.iter().position(|path| {
            path.path_context().is_some_and(|existing| existing.path_id == context.path_id)
        }).context("replacement TURN path identifier is not part of this group")?;
        anyhow::ensure!(
            !self.healthy[index].load(Ordering::Acquire),
            "cannot replace a healthy TURN path"
        );
        let replacement = Arc::new(replacement);
        let old = std::mem::replace(&mut paths[index], Arc::clone(&replacement));
        old.close();
        self.healthy[index].store(true, Ordering::Release);
        let path_health = Arc::clone(&self.healthy[index]);
        let downlink_sender = self.downlink_senders.lock()
            .map_err(|_| anyhow::anyhow!("TURN downlink sender registry is poisoned"))?
            .clone();
        let forwarder = tokio::spawn(async move {
            while let Ok(packet) = replacement.receive_packet().await {
                if downlink_sender.send(packet).await.is_err() {
                    break;
                }
            }
            path_health.store(false, Ordering::Release);
        });
        self.forwarders.lock()
            .map_err(|_| anyhow::anyhow!("TURN path forwarder registry is poisoned"))?
            .push(forwarder);
        Ok(())
    }

    /// Number of uplink IP packets dropped because their flow-affine path queue was full.
    pub fn uplink_queue_drops(&self) -> u64 {
        self.uplink_queue_drops.load(Ordering::Relaxed)
    }

    pub async fn send_packet(&self, packet: DataDatagram) -> Result<()> {
        let health: Vec<bool> = self.healthy.iter()
            .map(|path| path.load(Ordering::Acquire))
            .collect();
        let start = select_path_index(&packet.packet, &health)
            .context("TURN path group has no healthy paths")?;
        let paths = self.paths.read()
            .map_err(|_| anyhow::anyhow!("TURN path registry is poisoned"))?;
        for offset in 0..paths.len() {
            let index = (start + offset) % paths.len();
            if !self.healthy[index].load(Ordering::Acquire) {
                continue;
            }
            match enqueue_uplink_packet(
                &paths[index].uplink,
                packet.clone(),
                &self.uplink_queue_drops,
            ) {
                Ok(()) => return Ok(()),
                // Do not move a congested flow to another path: packets already
                // queued there would be overtaken. Drop newest and keep reading TUN.
                Err(mpsc::error::TrySendError::Full(_)) => return Ok(()),
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.healthy[index].store(false, Ordering::Release);
                }
            }
        }
        anyhow::bail!("all TURN paths rejected the packet or became unavailable")
    }

    pub async fn receive_packet(&self) -> Result<DataDatagram> {
        self.downlink.lock().await.recv().await
            .context("all TURN path downlink queues are closed")
    }

    pub fn close(&self) {
        if let Ok(tasks) = self.forwarders.lock() {
            for task in tasks.iter() { task.abort(); }
        }
        if let Ok(paths) = self.paths.read() {
            for path in paths.iter() { path.close(); }
        }
    }
}

impl Drop for TurnClientPathGroup {
    fn drop(&mut self) {
        if let Ok(tasks) = self.forwarders.get_mut() {
            for task in tasks.iter() { task.abort(); }
        }
        if let Ok(paths) = self.paths.get_mut() {
            for path in paths.iter() { path.close(); }
        }
    }
}

fn enqueue_uplink_packet(
    sender: &mpsc::Sender<DataDatagram>,
    packet: DataDatagram,
    dropped: &AtomicU64,
) -> std::result::Result<(), mpsc::error::TrySendError<DataDatagram>> {
    match sender.try_send(packet) {
        Ok(()) => Ok(()),
        Err(error @ mpsc::error::TrySendError::Full(_)) => {
            dropped.fetch_add(1, Ordering::Relaxed);
            Err(error)
        }
        Err(error) => Err(error),
    }
}

fn select_path_index(packet: &[u8], healthy: &[bool]) -> Option<usize> {
    if healthy.is_empty() {
        return None;
    }
    let start = (ghulakh_protocol::ip_flow::flow_hash(packet) as usize) % healthy.len();
    (0..healthy.len())
        .map(|offset| (start + offset) % healthy.len())
        .find(|index| healthy[*index])
}

#[cfg(test)]
mod path_group_tests {
    use super::*;

    fn packet(source_port: u16) -> Vec<u8> {
        let mut packet = vec![0u8; 24];
        packet[0] = 0x45;
        let length = packet.len() as u16;
        packet[2..4].copy_from_slice(&length.to_be_bytes());
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 77, 0, 2]);
        packet[16..20].copy_from_slice(&[203, 0, 113, 8]);
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&443u16.to_be_bytes());
        packet
    }

    #[test]
    fn flow_selection_is_stable_and_uses_other_healthy_paths_on_failure() {
        let healthy = [true, true, true, true];
        let first = select_path_index(&packet(12000), &healthy).unwrap();
        let second = select_path_index(&packet(12000), &healthy).unwrap();
        assert_eq!(first, second);

        let mut degraded = healthy;
        degraded[first] = false;
        let fallback = select_path_index(&packet(12000), &degraded).unwrap();
        assert_ne!(fallback, first);
        assert_eq!(select_path_index(&packet(12000), &[false; 4]), None);
    }

    #[tokio::test]
    async fn saturated_flow_queue_drops_newest_without_blocking_or_reassigning() {
        let (sender, mut receiver) = mpsc::channel(1);
        let dropped = AtomicU64::new(0);
        let first = DataDatagram { kind: ghulakh_protocol::IpPacketKind::Ipv4, packet: packet(12000) };
        let second = DataDatagram { kind: ghulakh_protocol::IpPacketKind::Ipv4, packet: packet(12001) };

        enqueue_uplink_packet(&sender, first.clone(), &dropped).unwrap();
        assert!(matches!(
            enqueue_uplink_packet(&sender, second, &dropped),
            Err(mpsc::error::TrySendError::Full(_))
        ));
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        assert_eq!(receiver.recv().await.unwrap(), first);
    }

    fn mock_path(
        path_id: u16,
        group_id: [u8; 16],
    ) -> (
        TurnClientRuntime,
        mpsc::Receiver<DataDatagram>,
        mpsc::Sender<DataDatagram>,
    ) {
        let (uplink, uplink_rx) = mpsc::channel(APP_QUEUE_CAPACITY);
        let (downlink_tx, downlink) = mpsc::channel(APP_QUEUE_CAPACITY);
        let pending_dataplane = tokio::spawn(async {
            std::future::pending::<Result<TurnDataPlaneStats>>().await
        });
        let pending_maintenance = tokio::spawn(async {
            std::future::pending::<Result<()>>().await
        });
        (
            TurnClientRuntime {
                config: ghulakh_protocol::session_handshake::TurnSessionConfig {
                    virtual_ipv4: "10.77.0.2".parse().unwrap(),
                    mtu: 1100,
                },
                path_context: Some(TurnPathContext {
                    group_id,
                    path_id,
                    path_count: 2,
                }),
                uplink,
                downlink: tokio::sync::Mutex::new(downlink),
                dataplane_task: pending_dataplane,
                maintenance_task: pending_maintenance,
            },
            uplink_rx,
            downlink_tx,
        )
    }

    #[tokio::test]
    async fn path_group_dispatches_merges_downlink_and_degrades_after_path_loss() {
        let group_id = [0x5a; 16];
        let (path_a, mut uplink_a, downlink_a) = mock_path(0, group_id);
        let (path_b, mut uplink_b, downlink_b) = mock_path(1, group_id);
        let group = TurnClientPathGroup::new(vec![path_a, path_b]).unwrap();
        assert_eq!(group.active_paths(), 2);

        // Uplink flow affinity must keep a flow on one path while distinct
        // flows can be distributed across the independent path queues.
        let mut selected_flows = [None, None];
        for source_port in 10000..10100 {
            let bytes = packet(source_port);
            let path = select_path_index(&bytes, &[true, true]).unwrap();
            if selected_flows[path].is_none() {
                selected_flows[path] = Some((path, bytes));
            }
            if selected_flows.iter().all(Option::is_some) {
                break;
            }
        }
        let selected_flows = selected_flows.map(Option::unwrap);
        for (expected_path, bytes) in selected_flows {
            let datagram = DataDatagram {
                kind: ghulakh_protocol::IpPacketKind::Ipv4,
                packet: bytes.clone(),
            };
            group.send_packet(datagram.clone()).await.unwrap();
            let received = if expected_path == 0 {
                uplink_a.recv().await.unwrap()
            } else {
                uplink_b.recv().await.unwrap()
            };
            assert_eq!(received, datagram);
            let other = if expected_path == 0 { &mut uplink_b } else { &mut uplink_a };
            assert!(other.try_recv().is_err());
        }

        // The downlink fan-in accepts packets from either independent path.
        let down_a = DataDatagram {
            kind: ghulakh_protocol::IpPacketKind::Ipv4,
            packet: packet(12001),
        };
        let down_b = DataDatagram {
            kind: ghulakh_protocol::IpPacketKind::Ipv4,
            packet: packet(12002),
        };
        downlink_a.send(down_a.clone()).await.unwrap();
        downlink_b.send(down_b.clone()).await.unwrap();
        let mut merged = vec![
            group.receive_packet().await.unwrap(),
            group.receive_packet().await.unwrap(),
        ];
        merged.sort_by_key(|packet| packet.packet[20..22].to_vec());
        assert_eq!(merged, vec![down_a, down_b]);

        // Closing one path's downlink makes the group unhealthy for that
        // path; subsequent flows are assigned to the surviving path.
        drop(downlink_a);
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            async {
                while group.active_paths() != 1 {
                    tokio::task::yield_now().await;
                }
            },
        ).await.unwrap();

        let mut failed_path_flow = None;
        for source_port in 20000..20100 {
            let bytes = packet(source_port);
            if select_path_index(&bytes, &[true, true]) == Some(0) {
                failed_path_flow = Some(bytes);
                break;
            }
        }
        let bytes = failed_path_flow.expect("a flow assigned to path zero exists");
        let datagram = DataDatagram {
            kind: ghulakh_protocol::IpPacketKind::Ipv4,
            packet: bytes,
        };
        group.send_packet(datagram.clone()).await.unwrap();
        assert_eq!(uplink_b.recv().await.unwrap(), datagram);
        assert!(uplink_a.try_recv().is_err());

        group.close();
    }

    #[tokio::test]
    async fn path_group_queue_saturation_drops_newest_without_reassigning_flow() {
        let group_id = [0x6b; 16];
        let (path_a, mut uplink_a, _downlink_a) = mock_path(0, group_id);
        let (path_b, mut uplink_b, _downlink_b) = mock_path(1, group_id);
        let group = TurnClientPathGroup::new(vec![path_a, path_b]).unwrap();

        let packet_bytes = packet(23456);
        let selected = select_path_index(&packet_bytes, &[true, true]).unwrap();
        let datagram = DataDatagram {
            kind: ghulakh_protocol::IpPacketKind::Ipv4,
            packet: packet_bytes,
        };

        for _ in 0..APP_QUEUE_CAPACITY {
            group.send_packet(datagram.clone()).await.unwrap();
        }
        assert_eq!(group.uplink_queue_drops(), 0);

        // A full flow-affine queue drops the newest packet; it must not move
        // that flow to another path and overtake packets already queued there.
        group.send_packet(datagram.clone()).await.unwrap();
        assert_eq!(group.uplink_queue_drops(), 1);

        let (selected_rx, other_rx) = if selected == 0 {
            (&mut uplink_a, &mut uplink_b)
        } else {
            (&mut uplink_b, &mut uplink_a)
        };
        for _ in 0..APP_QUEUE_CAPACITY {
            assert_eq!(selected_rx.recv().await.unwrap(), datagram);
        }
        assert!(selected_rx.try_recv().is_err());
        assert!(other_rx.try_recv().is_err());
        group.close();
    }

    #[test]
    fn different_flows_can_select_different_paths() {
        let healthy = [true, true, true, true];
        let selections: std::collections::HashSet<usize> =
            (10000..10064)
                .map(|port| select_path_index(&packet(port), &healthy).unwrap())
                .collect();
        assert!(selections.len() > 1);
    }
}
