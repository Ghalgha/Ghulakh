//! High-level TURN client session assembly.
//!
//! This composes the protected UDP socket, TURN allocation/authentication,
//! peer permission, channel binding, authenticated Noise handshake and bounded
//! bidirectional IP dataplane. VK API credential acquisition remains external.

use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    net::{SocketAddr, UdpSocket as StdUdpSocket},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, RwLock, Mutex as StdMutex,
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use ghulakh_protocol::{ordered_datagram::SequencedDataDatagram, DataDatagram, turn_path_context::TurnPathContext};
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
const DOWNLINK_REORDER_GAP_TIMEOUT: Duration = Duration::from_millis(250);
const DOWNLINK_REORDER_MAX_PENDING: usize = APP_QUEUE_CAPACITY * 2;

#[derive(Default)]
struct DownlinkReorderBuffer {
    expected_sequence: u64,
    pending: BTreeMap<u64, DataDatagram>,
    ready: VecDeque<DataDatagram>,
    gap_started: Option<Instant>,
}

impl DownlinkReorderBuffer {
    fn push(&mut self, packet: SequencedDataDatagram, now: Instant) {
        let Some(sequence) = packet.sequence else {
            if self.pending.is_empty() && self.ready.is_empty() {
                self.ready.push_back(packet.datagram);
            }
            return;
        };
        if sequence < self.expected_sequence {
            return;
        }
        if sequence > self.expected_sequence && self.pending.len() >= DOWNLINK_REORDER_MAX_PENDING {
            self.advance_gap(now);
            if sequence < self.expected_sequence {
                return;
            }
        }
        if sequence == self.expected_sequence {
            self.ready.push_back(packet.datagram);
            self.expected_sequence = self.expected_sequence.wrapping_add(1);
            self.drain(now);
        } else {
            self.pending.entry(sequence).or_insert(packet.datagram);
            self.gap_started.get_or_insert(now);
        }
    }

    fn drain(&mut self, now: Instant) {
        while let Some(packet) = self.pending.remove(&self.expected_sequence) {
            self.ready.push_back(packet);
            self.expected_sequence = self.expected_sequence.wrapping_add(1);
        }
        if self.pending.is_empty() {
            self.gap_started = None;
        } else {
            self.gap_started.get_or_insert(now);
        }
    }

    fn gap_deadline(&self) -> Option<Instant> {
        self.gap_started.map(|started| started + DOWNLINK_REORDER_GAP_TIMEOUT)
    }

    fn advance_gap(&mut self, now: Instant) {
        if let Some((&next_sequence, _)) = self.pending.first_key_value() {
            self.expected_sequence = next_sequence;
            self.gap_started = None;
            self.drain(now);
        } else {
            self.gap_started = None;
        }
    }

    #[cfg(test)]
    fn pop_ready(&mut self) -> Option<DataDatagram> {
        self.ready.pop_front()
    }
}

/// Fully assembled client-side TURN VPN dataplane.
pub struct TurnClientRuntime {
    config: ghulakh_protocol::session_handshake::TurnSessionConfig,
    path_context: Option<TurnPathContext>,
    uplink: mpsc::Sender<DataDatagram>,
    downlink: tokio::sync::Mutex<mpsc::Receiver<SequencedDataDatagram>>,
    dataplane_task: JoinHandle<Result<TurnDataPlaneStats>>,
    maintenance_task: JoinHandle<Result<()>>,
    shutdown_signal: watch::Sender<bool>,
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
        let path_id = path_context.as_ref().map_or(0, |context| context.path_id);
        let mut seen_endpoints = HashSet::new();
        let mut relay_addresses = Vec::new();
        for endpoint in credentials.endpoints().iter().filter(|endpoint| {
            endpoint.scheme == TurnScheme::Turn && endpoint.transport == TurnWireTransport::Udp
        }) {
            // Multiple URI variants for the same host:port are one candidate.
            let authority = endpoint.socket_authority().to_ascii_lowercase();
            if !seen_endpoints.insert(authority) {
                continue;
            }
            let addresses = tokio::net::lookup_host((endpoint.host.as_str(), endpoint.port)).await;
            append_resolved_relay_addresses(
                &mut relay_addresses,
                addresses,
                local_address.is_ipv4(),
            );
        }
        let relay_endpoint = select_relay_address(relay_addresses, path_id)
            .context("VK Calls response has no resolvable UDP TURN endpoint for the protected socket family")?;

        let socket = TurnUdpSocket::from_protected_socket(protected_socket, relay_endpoint)
            .context("adopt protected VK Calls TURN socket")?;
        let driver = TurnClientDriver::new(socket)
            .with_requested_relay_family(gateway_peer.is_ipv4());
        let provider = VkCallsTurnAuthProvider::from_credentials(credentials)
            .context("initialize VK Calls TURN authentication provider")?;
        let mut supervisor = TurnSessionSupervisor::new(driver, provider);

        supervisor.allocate().await.context("create VK Calls TURN allocation")?;
        if let Err(error) = supervisor.create_permission(&[gateway_peer]).await {
            return Err(release_failed_turn_setup(
                &mut supervisor, error, "create TURN permission for VPN gateway",
            ).await);
        }
        if let Err(error) = supervisor.channel_bind(DEFAULT_TURN_CHANNEL, gateway_peer).await {
            return Err(release_failed_turn_setup(
                &mut supervisor, error, "bind TURN channel to VPN gateway",
            ).await);
        }

        let relay_endpoint = supervisor.relay_endpoint();
        let (handshake_socket, handshake_inbound) =
            match supervisor.take_handshake_plane_parts() {
                Some(parts) => parts,
                None => {
                    return Err(release_failed_turn_setup(
                        &mut supervisor,
                        anyhow::anyhow!("TURN handshake queue is unavailable"),
                        "take isolated TURN handshake queue",
                    ).await);
                }
            };
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
        let TurnClientSession { frame_keys, config } = match handshake {
            Ok(session) => session,
            Err(error) => {
                return Err(release_failed_turn_setup(
                    &mut supervisor, error, "authenticate VPN session over TURN",
                ).await);
            }
        };

        let (data_socket, data_inbound) = match supervisor.take_data_plane_parts() {
            Some(parts) => parts,
            None => {
                return Err(release_failed_turn_setup(
                    &mut supervisor,
                    anyhow::anyhow!("TURN dataplane queue is unavailable"),
                    "take TURN dataplane queue",
                ).await);
            }
        };
        let (uplink_sealer, downlink_opener) = frame_keys.into_client_codecs();
        let plane = TurnDataPlane::new(
            data_socket,
            data_inbound,
            relay_endpoint,
            TurnDataSender::new(DEFAULT_TURN_CHANNEL, uplink_sealer),
            TurnDataReceiver::new(DEFAULT_TURN_CHANNEL, downlink_opener),
        );
        let (uplink, uplink_rx) = mpsc::channel(APP_QUEUE_CAPACITY);
        let (downlink_tx, downlink) = mpsc::channel::<SequencedDataDatagram>(APP_QUEUE_CAPACITY);
        let (maintenance_stopped_tx, mut maintenance_stopped_rx) = watch::channel(false);
        let (shutdown_signal, mut shutdown_rx) = watch::channel(false);
        let maintenance_task = tokio::spawn(async move {
            let result = tokio::select! {
                result = supervisor.maintain_allocation() => {
                    match result {
                        Ok(()) => {
                            supervisor.close();
                            Ok(())
                        }
                        Err(error) => {
                            let cleanup = tokio::time::timeout(
                                std::time::Duration::from_secs(3),
                                supervisor.deallocate(),
                            ).await;
                            supervisor.close();
                            match cleanup {
                                Ok(Ok(())) => Err(error.context("TURN maintenance stopped; allocation deallocated")),
                                Ok(Err(cleanup_error)) => Err(error.context(format!(
                                    "TURN maintenance stopped; allocation cleanup failed: {cleanup_error:#}"
                                ))),
                                Err(_) => Err(error.context(
                                    "TURN maintenance stopped; allocation cleanup timed out after 3 seconds"
                                )),
                            }
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    let cleanup = tokio::time::timeout(
                        std::time::Duration::from_secs(3),
                        supervisor.deallocate(),
                    ).await;
                    supervisor.close();
                    match cleanup {
                        Ok(Ok(())) => Ok(()),
                        Ok(Err(error)) => Err(error.context("deallocate TURN allocation during shutdown")),
                        Err(_) => Err(anyhow::anyhow!(
                            "TURN allocation deallocation timed out after 3 seconds during shutdown"
                        )),
                    }
                }
            };
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
            shutdown_signal,
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

    pub async fn receive_packet(&self) -> Result<SequencedDataDatagram> {
        self.downlink.lock().await.recv().await.context("TURN VPN downlink queue closed")
    }

    pub fn dataplane_finished(&self) -> bool {
        self.dataplane_task.is_finished() || self.maintenance_task.is_finished()
    }

    pub fn close(&self) {
        self.shutdown_signal.send_replace(true);
        self.dataplane_task.abort();
    }
}

impl Drop for TurnClientRuntime {
    fn drop(&mut self) {
        self.shutdown_signal.send_replace(true);
        self.dataplane_task.abort();
    }
}


/// Release an allocation when path setup fails after Allocate succeeded.
async fn release_failed_turn_setup(
    supervisor: &mut TurnSessionSupervisor<VkCallsTurnAuthProvider>,
    error: anyhow::Error,
    context: &'static str,
) -> anyhow::Error {
    let cleanup = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        supervisor.deallocate(),
    ).await;
    supervisor.close();
    match cleanup {
        Ok(Ok(())) => error.context(context),
        Ok(Err(cleanup_error)) => error.context(format!(
            "{context}; TURN allocation cleanup failed: {cleanup_error:#}"
        )),
        Err(_) => error.context(format!(
            "{context}; TURN allocation cleanup timed out after 3 seconds"
        )),
    }
}

/// Bounded retry policy for recreating one failed TURN allocation.
#[derive(Clone, Debug)]
pub struct TurnPathRecoveryPolicy {
    consecutive_failures: u32,
    maximum_delay: std::time::Duration,
}

impl Default for TurnPathRecoveryPolicy {
    fn default() -> Self {
        Self {
            consecutive_failures: 0,
            maximum_delay: std::time::Duration::from_secs(30),
        }
    }
}

impl TurnPathRecoveryPolicy {
    pub fn new(maximum_delay: std::time::Duration) -> Result<Self> {
        anyhow::ensure!(!maximum_delay.is_zero(), "TURN path recovery delay cap must be non-zero");
        // Callers may lower the cap, but cannot exceed the Android policy.
        let maximum_delay = maximum_delay.min(std::time::Duration::from_secs(30));
        Ok(Self { consecutive_failures: 0, maximum_delay })
    }

    /// Return capped exponential backoff: 1, 2, 4, 8, 16, then at most 30 seconds.
    pub fn record_failure(&mut self) -> std::time::Duration {
        let exponent = self.consecutive_failures.min(5);
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        std::time::Duration::from_secs(1u64 << exponent).min(self.maximum_delay)
    }

    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
    }

    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }
}

/// One logical VPN tunnel backed by several independent authenticated TURN paths.
/// Per-flowlet scheduling spreads sustained bulk traffic while keeping small
/// latency-sensitive UDP flows pinned to one path.
pub struct TurnClientPathGroup {
    config: ghulakh_protocol::session_handshake::TurnSessionConfig,
    paths: RwLock<Vec<Arc<TurnClientRuntime>>>,
    healthy: Vec<Arc<AtomicBool>>,
    downlink: tokio::sync::Mutex<mpsc::Receiver<SequencedDataDatagram>>,
    downlink_senders: StdMutex<mpsc::Sender<SequencedDataDatagram>>,
    downlink_reorder: tokio::sync::Mutex<DownlinkReorderBuffer>,
    forwarders: StdMutex<Vec<JoinHandle<()>>>,
    uplink_scheduler: StdMutex<UplinkScheduler>,
    uplink_queue_drops: AtomicU64,
    closed: AtomicBool,
    closed_signal: watch::Sender<bool>,
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
            anyhow::ensure!(path.config() == config, "TURN paths disagree on tunnel IPv4, IPv6, or MTU");
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
        let (closed_signal, _) = watch::channel(false);
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
            downlink_reorder: tokio::sync::Mutex::new(DownlinkReorderBuffer::default()),
            forwarders: StdMutex::new(forwarders),
            uplink_scheduler: StdMutex::new(UplinkScheduler::default()),
            uplink_queue_drops: AtomicU64::new(0),
            closed: AtomicBool::new(false),
            closed_signal,
        })
    }

    pub fn config(&self) -> ghulakh_protocol::session_handshake::TurnSessionConfig {
        self.config
    }

    pub fn active_paths(&self) -> usize {
        self.healthy.iter().filter(|path| path.load(Ordering::Acquire)).count()
    }

    /// Authenticated metadata for a path slot, including a failed slot.
    pub fn path_context(&self, path_id: u16) -> Option<TurnPathContext> {
        self.paths.read().ok()?.iter().find_map(|path| {
            path.path_context().filter(|context| context.path_id == path_id)
        })
    }

    /// Path identifiers whose dataplane or allocation maintenance has stopped.
    pub fn failed_path_ids(&self) -> Vec<u16> {
        let Ok(paths) = self.paths.read() else { return Vec::new() };
        paths.iter().enumerate().filter_map(|(index, path)| {
            (!self.healthy.get(index)?.load(Ordering::Acquire))
                .then(|| path.path_context().map(|context| context.path_id)).flatten()
        }).collect()
    }

    /// Atomically replace one failed path after a fresh authenticated TURN handshake.
    pub fn replace_path(&self, replacement: TurnClientRuntime) -> Result<()> {
        anyhow::ensure!(replacement.config() == self.config, "replacement TURN path changed tunnel IPv4, IPv6, or MTU");
        let context = replacement.path_context()
            .context("replacement TURN path has no authenticated path context")?;
        context.validate().context("validate replacement TURN path context")?;
        let mut paths = self.paths.write()
            .map_err(|_| anyhow::anyhow!("TURN path registry is poisoned"))?;
        anyhow::ensure!(!self.closed.load(Ordering::Acquire), "TURN path group is closed");
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
        // Acquire every fallible registry lock before mutating the path slot.
        // Forwarders are indexed in the same stable order as path slots.
        let downlink_sender = self.downlink_senders.lock()
            .map_err(|_| anyhow::anyhow!("TURN downlink sender registry is poisoned"))?
            .clone();
        let mut forwarders = self.forwarders.lock()
            .map_err(|_| anyhow::anyhow!("TURN path forwarder registry is poisoned"))?;
        anyhow::ensure!(index < forwarders.len(), "TURN path forwarder slot is missing");

        let replacement = Arc::new(replacement);
        let old = std::mem::replace(&mut paths[index], Arc::clone(&replacement));
        // Cancel the previous watcher before publishing the replacement as
        // healthy. Otherwise its late completion could mark the new path dead.
        forwarders[index].abort();
        old.close();

        // Publish the slot as healthy before its watcher can run. If the
        // replacement has already failed, the watcher must be the final
        // writer and leave the slot unhealthy.
        self.healthy[index].store(true, Ordering::Release);
        let path_health = Arc::clone(&self.healthy[index]);
        let forwarder = tokio::spawn(async move {
            while let Ok(packet) = replacement.receive_packet().await {
                if downlink_sender.send(packet).await.is_err() {
                    break;
                }
            }
            path_health.store(false, Ordering::Release);
        });
        forwarders[index] = forwarder;
        Ok(())
    }

    /// Number of uplink IP packets dropped because their flow-affine path queue was full.
    pub fn uplink_queue_drops(&self) -> u64 {
        self.uplink_queue_drops.load(Ordering::Relaxed)
    }

    pub async fn send_packet(&self, packet: DataDatagram) -> Result<()> {
        let closed = self.closed_signal.subscribe();
        anyhow::ensure!(
            !self.closed.load(Ordering::Acquire) && !*closed.borrow(),
            "TURN path group is closed"
        );
        let paths = self.paths.read()
            .map_err(|_| anyhow::anyhow!("TURN path registry is poisoned"))?;
        let now = Instant::now();
        let mut scheduler = self.uplink_scheduler.lock()
            .map_err(|_| anyhow::anyhow!("TURN uplink scheduler lock poisoned"))?;
        let mut pending = packet;
        for _ in 0..paths.len() {
            let healthy: Vec<bool> = self.healthy.iter()
                .map(|path| path.load(Ordering::Acquire))
                .collect();
            let sendable: Vec<bool> = paths.iter().enumerate().map(|(index, path)| {
                healthy[index] && !path.uplink.is_closed() && path.uplink.capacity() > 0
            }).collect();
            let Some(index) = scheduler.select(&healthy, &sendable, &pending.packet, now) else {
                self.uplink_queue_drops.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            };
            match paths[index].uplink.try_send(pending) {
                Ok(()) => return Ok(()),
                Err(mpsc::error::TrySendError::Full(_)) => {
                    // The queue filled after the capacity snapshot. Drop newest;
                    // do not send it on another path and overtake queued packets.
                    self.uplink_queue_drops.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
                Err(mpsc::error::TrySendError::Closed(returned)) => {
                    self.healthy[index].store(false, Ordering::Release);
                    pending = returned;
                }
            }
        }
        self.uplink_queue_drops.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub async fn receive_packet(&self) -> Result<DataDatagram> {
        enum Event {
            Packet(Option<SequencedDataDatagram>),
            Gap,
        }
        let mut closed = self.closed_signal.subscribe();
        if self.closed.load(Ordering::Acquire) || *closed.borrow() {
            anyhow::bail!("TURN path group is closed");
        }
        let mut downlink = self.downlink.lock().await;
        let mut reorder = self.downlink_reorder.lock().await;
        loop {
            if let Some(packet) = reorder.ready.pop_front() {
                return Ok(packet);
            }
            let event = if let Some(deadline) = reorder.gap_deadline() {
                tokio::select! {
                    biased;
                    _ = closed.changed() => anyhow::bail!("TURN path group is closed"),
                    packet = downlink.recv() => Event::Packet(packet),
                    _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => Event::Gap,
                }
            } else {
                tokio::select! {
                    biased;
                    _ = closed.changed() => anyhow::bail!("TURN path group is closed"),
                    packet = downlink.recv() => Event::Packet(packet),
                }
            };
            match event {
                Event::Packet(Some(packet)) => reorder.push(packet, Instant::now()),
                Event::Packet(None) => anyhow::bail!("all TURN path downlink queues are closed"),
                Event::Gap => reorder.advance_gap(Instant::now()),
            }
        }
    }

    pub async fn closed(&self) {
        let mut signal = self.closed_signal.subscribe();
        if !self.closed.load(Ordering::Acquire) && !*signal.borrow() {
            let _ = signal.changed().await;
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub fn close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.closed_signal.send_replace(true);
        }
        // Keep the same lock order as replace_path(): path registry before
        // forwarder registry. Reversing these locks can deadlock shutdown
        // against a concurrent path replacement.
        let paths = self.paths.write().unwrap_or_else(|poisoned| poisoned.into_inner());
        let forwarders = self.forwarders.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        for task in forwarders.iter() { task.abort(); }
        for path in paths.iter() { path.close(); }
    }
}

impl Drop for TurnClientPathGroup {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
        self.closed_signal.send_replace(true);
        if let Ok(tasks) = self.forwarders.get_mut() {
            for task in tasks.iter() { task.abort(); }
        }
        if let Ok(paths) = self.paths.get_mut() {
            for path in paths.iter() { path.close(); }
        }
    }
}


fn append_resolved_relay_addresses<I, E>(
    target: &mut Vec<SocketAddr>,
    resolved: std::result::Result<I, E>,
    local_is_ipv4: bool,
)
where
    I: IntoIterator<Item = SocketAddr>,
{
    if let Ok(addresses) = resolved {
        target.extend(addresses.into_iter().filter(|address| {
            address.is_ipv4() == local_is_ipv4
        }));
    }
}

fn select_relay_address(mut addresses: Vec<SocketAddr>, path_id: u16) -> Option<SocketAddr> {
    addresses.sort_unstable();
    addresses.dedup();
    (!addresses.is_empty()).then(|| addresses[usize::from(path_id) % addresses.len()])
}

const UPLINK_RATE_BYTES_PER_SEC: f64 = 247_000.0;
const UPLINK_BUCKET_CAPACITY: f64 = 10_500.0;
const UPLINK_MAX_DEFICIT: f64 = -4_500.0;
// Keep each uplink flow on one TURN allocation; downlink striping is sequenced and reordered.
const UPLINK_FLOW_BURST_BYTES: usize = usize::MAX;
const UPLINK_FLOW_TABLE_MAX: usize = 1024;
const UPLINK_FLOW_EVICT_EVERY: u32 = 1024;
const UPLINK_FLOW_IDLE_TTL: Duration = Duration::from_secs(30);
const UPLINK_SMALL_UDP_MAX_LEN: usize = 300;
const UPLINK_SMALL_UDP_STICKY: Duration = Duration::from_secs(1);
const UPLINK_PIN_WINDOW: Duration = Duration::from_millis(250);
const UPLINK_PIN_WINDOW_MAX_BYTES: usize =
    (UPLINK_RATE_BYTES_PER_SEC as usize) * 3 / 4 / 4;
const UPLINK_BULK_HOLD: Duration = Duration::from_secs(2);

#[derive(Clone, Copy)]
struct UplinkFlowState {
    path_index: usize,
    last_seen: Instant,
    burst_left: usize,
    sticky_until: Option<Instant>,
    window_start: Instant,
    window_bytes: usize,
    bulk_until: Option<Instant>,
}

impl UplinkFlowState {
    fn new(path_index: usize, now: Instant, packet_len: usize, small_udp: bool) -> Self {
        Self {
            path_index,
            last_seen: now,
            burst_left: UPLINK_FLOW_BURST_BYTES.saturating_sub(packet_len),
            sticky_until: small_udp.then_some(now + UPLINK_SMALL_UDP_STICKY),
            window_start: now,
            window_bytes: packet_len,
            bulk_until: None,
        }
    }

    fn keeps_pin(&mut self, now: Instant, packet_len: usize, small_udp: bool) -> bool {
        if now.saturating_duration_since(self.window_start) >= UPLINK_PIN_WINDOW {
            self.window_start = now;
            self.window_bytes = 0;
        }
        self.window_bytes = self.window_bytes.saturating_add(packet_len);
        if self.window_bytes > UPLINK_PIN_WINDOW_MAX_BYTES {
            self.bulk_until = Some(now + UPLINK_BULK_HOLD);
            self.sticky_until = None;
        }
        let bulk = self.bulk_until.is_some_and(|until| now < until);
        if small_udp && !bulk {
            self.sticky_until = Some(now + UPLINK_SMALL_UDP_STICKY);
        }
        self.sticky_until.is_some_and(|until| now < until)
    }
}

#[derive(Clone, Copy)]
struct UplinkRateController {
    rate: f64,
    congested: bool,
    last_adjust: Option<Instant>,
}

impl UplinkRateController {
    fn new() -> Self {
        Self {
            rate: UPLINK_RATE_BYTES_PER_SEC,
            congested: false,
            last_adjust: None,
        }
    }

    fn mark_congested(&mut self) {
        self.congested = true;
    }

    fn tick(&mut self, now: Instant) {
        let Some(last) = self.last_adjust else {
            self.last_adjust = Some(now);
            return;
        };
        if now.saturating_duration_since(last) < Duration::from_millis(100) {
            return;
        }
        if self.congested {
            self.rate = (self.rate * 0.85).max(150_000.0);
            self.congested = false;
        } else {
            self.rate = (self.rate + 5_000.0).min(UPLINK_RATE_BYTES_PER_SEC);
        }
        self.last_adjust = Some(now);
    }
}

#[derive(Default)]
struct UplinkScheduler {
    last_update: Option<Instant>,
    tokens: Vec<f64>,
    rates: Vec<UplinkRateController>,
    cursor: usize,
    flows: HashMap<ghulakh_protocol::ip_flow::IpFlowKey, UplinkFlowState>,
    flow_evict_counter: u32,
}

impl UplinkScheduler {
    fn update_tokens(&mut self, count: usize, now: Instant) {
        if self.tokens.len() != count {
            self.tokens.resize(count, UPLINK_BUCKET_CAPACITY);
            self.rates.resize_with(count, UplinkRateController::new);
            self.last_update = Some(now);
            self.flows.clear();
            self.flow_evict_counter = 0;
        }
        for rate in &mut self.rates {
            rate.tick(now);
        }
        let start = self.last_update.unwrap_or(now);
        let elapsed = now.saturating_duration_since(start).as_secs_f64();
        if elapsed >= 0.0001 {
            self.last_update = Some(now);
            for (tokens, rate) in self.tokens.iter_mut().zip(self.rates.iter()) {
                *tokens = (*tokens + elapsed * rate.rate).min(UPLINK_BUCKET_CAPACITY);
            }
        }
    }

    fn evict_flows(&mut self, now: Instant) {
        self.flow_evict_counter = self.flow_evict_counter.wrapping_add(1);
        if !self.flow_evict_counter.is_multiple_of(UPLINK_FLOW_EVICT_EVERY)
            && self.flows.len() < UPLINK_FLOW_TABLE_MAX
        {
            return;
        }
        self.flows.retain(|_, state| {
            now.saturating_duration_since(state.last_seen) < UPLINK_FLOW_IDLE_TTL
        });
        if self.flows.len() >= UPLINK_FLOW_TABLE_MAX {
            self.flows.clear();
        }
    }

    fn choose_path(&mut self, healthy: &[bool], sendable: &[bool]) -> Option<usize> {
        let count = sendable.len();
        if count == 0 {
            return None;
        }
        let start = self.cursor.min(count - 1);
        let mut best_index = None;
        let mut best_tokens = f64::NEG_INFINITY;
        for offset in 0..count {
            let index = (start + offset) % count;
            if !healthy[index] {
                continue;
            }
            if !sendable[index] {
                self.rates[index].mark_congested();
                continue;
            }
            if self.tokens[index] > best_tokens {
                best_tokens = self.tokens[index];
                best_index = Some(index);
            }
        }
        if let Some(index) = best_index {
            self.cursor = (index + 1) % count;
        }
        best_index
    }

    fn charge(&mut self, index: usize, packet_len: usize) {
        self.tokens[index] =
            (self.tokens[index] - packet_len as f64).max(UPLINK_MAX_DEFICIT);
    }

    fn select(
        &mut self,
        healthy: &[bool],
        sendable: &[bool],
        packet: &[u8],
        now: Instant,
    ) -> Option<usize> {
        let count = sendable.len();
        if count == 0 || healthy.len() != count {
            return None;
        }
        self.update_tokens(count, now);
        let packet_len = packet.len();
        let Some(key) = ghulakh_protocol::ip_flow::ip_flow_key(packet) else {
            let index = self.choose_path(healthy, sendable)?;
            self.charge(index, packet_len);
            return Some(index);
        };

        self.evict_flows(now);
        let small_udp = key.protocol() == 17 && packet_len <= UPLINK_SMALL_UDP_MAX_LEN;
        if let Some(mut state) = self.flows.get(&key).copied() {
            state.last_seen = now;
            let sticky = state.keeps_pin(now, packet_len, small_udp);
            let assigned_sendable = state.path_index < count
                && healthy[state.path_index]
                && sendable[state.path_index];
            if assigned_sendable && (sticky || state.burst_left >= packet_len) {
                let index = state.path_index;
                state.burst_left = state.burst_left.saturating_sub(packet_len);
                self.flows.insert(key, state);
                self.charge(index, packet_len);
                return Some(index);
            }

            let index = self.choose_path(healthy, sendable)?;
            state.path_index = index;
            state.burst_left = UPLINK_FLOW_BURST_BYTES.saturating_sub(packet_len);
            self.flows.insert(key, state);
            self.charge(index, packet_len);
            return Some(index);
        }

        let index = self.choose_path(healthy, sendable)?;
        self.flows.insert(
            key,
            UplinkFlowState::new(index, now, packet_len, small_udp),
        );
        self.charge(index, packet_len);
        Some(index)
    }
}

#[cfg(test)]
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

#[cfg(test)]
mod path_group_tests {
    use super::*;


    #[test]
    fn relay_address_selection_is_stable_and_deduplicates_dns_answers() {
        let a = "192.0.2.10:3478".parse().unwrap();
        let b = "192.0.2.11:3478".parse().unwrap();
        let candidates = vec![b, a, b, a];
        assert_eq!(select_relay_address(candidates.clone(), 0), Some(a));
        assert_eq!(select_relay_address(candidates.clone(), 1), Some(b));
        assert_eq!(select_relay_address(candidates, 2), Some(a));
    }

    #[test]
    fn relay_dns_failure_does_not_discard_other_valid_endpoints() {
        let mut candidates = Vec::new();
        append_resolved_relay_addresses(
            &mut candidates,
            Err::<Vec<SocketAddr>, _>(std::io::Error::new(std::io::ErrorKind::NotFound, "DNS failure")),
            true,
        );
        append_resolved_relay_addresses(
            &mut candidates,
            Ok::<Vec<SocketAddr>, std::io::Error>(vec![
                "192.0.2.10:3478".parse().unwrap(),
                "[2001:db8::10]:3478".parse().unwrap(),
            ]),
            true,
        );
        assert_eq!(candidates, vec!["192.0.2.10:3478".parse().unwrap()]);
    }

    #[test]
    fn relay_address_selection_returns_none_for_no_matching_family_candidates() {
        assert_eq!(select_relay_address(Vec::new(), 0), None);
    }

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
    fn recovery_backoff_is_bounded_and_resets_after_success() {
        let mut policy = TurnPathRecoveryPolicy::default();
        let delays: Vec<_> = (0..8).map(|_| policy.record_failure().as_secs()).collect();
        assert_eq!(delays, vec![1, 2, 4, 8, 16, 30, 30, 30]);
        assert_eq!(policy.consecutive_failures(), 8);
        policy.record_success();
        assert_eq!(policy.consecutive_failures(), 0);
        assert_eq!(policy.record_failure().as_secs(), 1);
    }

    #[test]
    fn recovery_backoff_rejects_zero_custom_cap() {
        assert!(TurnPathRecoveryPolicy::new(std::time::Duration::ZERO).is_err());
    }

    #[test]
    fn recovery_backoff_custom_cap_cannot_exceed_android_limit() {
        let mut policy = TurnPathRecoveryPolicy::new(std::time::Duration::from_secs(120)).unwrap();
        let delays: Vec<_> = (0..8).map(|_| policy.record_failure().as_secs()).collect();
        assert_eq!(delays, vec![1, 2, 4, 8, 16, 30, 30, 30]);
    }

    #[test]
    fn recovery_backoff_allows_a_lower_custom_cap() {
        let mut policy = TurnPathRecoveryPolicy::new(std::time::Duration::from_secs(5)).unwrap();
        let delays: Vec<_> = (0..7).map(|_| policy.record_failure().as_secs()).collect();
        assert_eq!(delays, vec![1, 2, 4, 5, 5, 5, 5]);
    }

    fn bulk_packet(source_port: u16) -> Vec<u8> {
        let mut packet = vec![0u8; 1_300];
        packet[0] = 0x45;
        let length = packet.len() as u16;
        packet[2..4].copy_from_slice(&length.to_be_bytes());
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[10, 77, 0, 2]);
        packet[16..20].copy_from_slice(&[203, 0, 113, 8]);
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&443u16.to_be_bytes());
        packet
    }

    #[test]
    fn small_udp_flow_remains_pinned_to_one_healthy_path() {
        let mut scheduler = UplinkScheduler::default();
        let healthy = [true; 10];
        let sendable = [true; 10];
        let packet = packet(12000);
        let start = Instant::now();
        let first = scheduler.select(&healthy, &sendable, &packet, start).unwrap();
        for offset in 1..50 {
            let selected = scheduler.select(
                &healthy,
                &sendable,
                &packet,
                start + Duration::from_millis(offset),
            ).unwrap();
            assert_eq!(selected, first);
        }
    }

    #[test]
    fn sustained_bulk_flow_remains_pinned_across_burst_boundaries() {
        let mut scheduler = UplinkScheduler::default();
        let healthy = [true; 10];
        let sendable = [true; 10];
        let packet = bulk_packet(12000);
        let start = Instant::now();
        let first = scheduler.select(&healthy, &sendable, &packet, start).unwrap();
        for offset in 1..4_000u64 {
            let selected = scheduler.select(
                &healthy,
                &sendable,
                &packet,
                start + Duration::from_micros(offset * 520),
            ).unwrap();
            assert_eq!(selected, first, "one uplink flow must not switch paths at a burst boundary");
        }
    }

    #[test]
    fn independent_flows_are_distributed_across_healthy_paths() {
        let mut scheduler = UplinkScheduler::default();
        let healthy = [true; 10];
        let sendable = [true; 10];
        let start = Instant::now();
        let mut selected = [false; 10];
        for source_port in 10_000..11_000 {
            let index = scheduler.select(
                &healthy,
                &sendable,
                &packet(source_port),
                start,
            ).unwrap();
            selected[index] = true;
        }
        assert!(selected.into_iter().all(|path| path));
    }

    #[test]
    fn failed_or_backpressured_path_is_not_selected_for_new_flowlet() {
        let mut scheduler = UplinkScheduler::default();
        let healthy = [true; 4];
        let sendable = [true; 4];
        let packet = packet(12000);
        let start = Instant::now();
        let first = scheduler.select(&healthy, &sendable, &packet, start).unwrap();
        let mut degraded = healthy;
        degraded[first] = false;
        let replacement = scheduler.select(
            &degraded,
            &sendable,
            &packet,
            start + Duration::from_millis(1),
        ).unwrap();
        assert_ne!(replacement, first);
        let mut backpressured = [true; 4];
        backpressured[replacement] = false;
        let next = scheduler.select(
            &healthy,
            &backpressured,
            &packet,
            start + Duration::from_millis(2),
        ).unwrap();
        assert_ne!(next, replacement);
        assert_eq!(scheduler.select(&[false; 4], &[false; 4], &packet, start), None);
    }

    #[tokio::test]
    async fn closing_group_wakes_blocked_downlink_receive() {
        let group_id = [0x31; 16];
        let (path_a, _uplink_a, _downlink_a) = mock_path(0, group_id);
        let (path_b, _uplink_b, _downlink_b) = mock_path(1, group_id);
        let group = Arc::new(TurnClientPathGroup::new(vec![path_a, path_b]).unwrap());
        let receiver = {
            let group = Arc::clone(&group);
            tokio::spawn(async move { group.receive_packet().await })
        };
        tokio::task::yield_now().await;
        group.close();
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), receiver)
            .await
            .expect("close must wake a blocked receive")
            .expect("receive task must not panic");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn closed_group_rejects_late_path_replacement() {
        let group_id = [0x32; 16];
        let (path_a, _uplink_a, downlink_a) = mock_path(0, group_id);
        let (path_b, _uplink_b, downlink_b) = mock_path(1, group_id);
        let group = TurnClientPathGroup::new(vec![path_a, path_b]).unwrap();
        drop(downlink_b);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while group.failed_path_ids() != vec![1] {
                tokio::task::yield_now().await;
            }
        }).await.unwrap();
        group.close();
        let (replacement, _replacement_uplink, _replacement_downlink) = mock_path(1, group_id);
        assert!(group.replace_path(replacement).is_err());
        drop(downlink_a);
    }

    #[tokio::test]
    async fn concurrent_path_replacement_and_close_complete_without_deadlock() {
        for attempt in 0..16u8 {
            let group_id = [attempt.saturating_add(1); 16];
            let (path_a, _uplink_a, _downlink_a) = mock_path(0, group_id);
            let (path_b, _uplink_b, downlink_b) = mock_path(1, group_id);
            let group = Arc::new(TurnClientPathGroup::new(vec![path_a, path_b]).unwrap());
            drop(downlink_b);
            tokio::time::timeout(Duration::from_secs(1), async {
                while group.failed_path_ids() != vec![1] {
                    tokio::task::yield_now().await;
                }
            }).await.unwrap();

            let (replacement, _replacement_uplink, _replacement_downlink) = mock_path(1, group_id);
            let barrier = Arc::new(std::sync::Barrier::new(3));
            let runtime = tokio::runtime::Handle::current();
            let replace_group = Arc::clone(&group);
            let replace_barrier = Arc::clone(&barrier);
            let replace_runtime = runtime.clone();
            let replace_thread = std::thread::spawn(move || {
                let _entered = replace_runtime.enter();
                replace_barrier.wait();
                replace_group.replace_path(replacement)
            });
            let close_group = Arc::clone(&group);
            let close_barrier = Arc::clone(&barrier);
            let close_thread = std::thread::spawn(move || {
                close_barrier.wait();
                close_group.close();
            });
            barrier.wait();

            let deadline = Instant::now() + Duration::from_secs(2);
            while (!replace_thread.is_finished() || !close_thread.is_finished())
                && Instant::now() < deadline
            {
                tokio::task::yield_now().await;
            }
            assert!(replace_thread.is_finished(), "path replacement deadlocked with close()");
            assert!(close_thread.is_finished(), "close() deadlocked with path replacement");
            let _ = replace_thread.join().unwrap();
            close_thread.join().unwrap();
            assert!(group.is_closed());
        }
    }

    #[tokio::test]
    async fn failed_path_can_be_replaced_without_rebuilding_the_group() {
        let group_id = [0x6b; 16];
        let (path_a, _uplink_a, downlink_a) = mock_path(0, group_id);
        let (path_b, _uplink_b, downlink_b) = mock_path(1, group_id);
        let group = TurnClientPathGroup::new(vec![path_a, path_b]).unwrap();
        assert_eq!(group.active_paths(), 2);

        drop(downlink_b);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while group.failed_path_ids() != vec![1] {
                tokio::task::yield_now().await;
            }
        }).await.unwrap();
        assert_eq!(group.path_context(1).unwrap().group_id, group_id);

        let (replacement, mut replacement_uplink, _replacement_downlink) = mock_path(1, group_id);
        group.replace_path(replacement).unwrap();
        tokio::task::yield_now().await;
        assert_eq!(group.active_paths(), 2);
        assert!(group.failed_path_ids().is_empty());

        // Prove the replacement remains usable after the other allocation fails.
        drop(downlink_a);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while group.failed_path_ids() != vec![0] {
                tokio::task::yield_now().await;
            }
        }).await.unwrap();

        let packet = packet(10000);
        group.send_packet(DataDatagram {
            kind: ghulakh_protocol::IpPacketKind::Ipv4,
            packet: packet.clone(),
        }).await.unwrap();
        let received = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            replacement_uplink.recv(),
        ).await.unwrap().unwrap();
        assert_eq!(received.packet, packet);
    }


    #[tokio::test]
    async fn replacement_that_fails_immediately_is_marked_unhealthy() {
        let group_id = [0x7e; 16];
        let (path_a, _uplink_a, _downlink_a) = mock_path(0, group_id);
        let (path_b, _uplink_b, downlink_b) = mock_path(1, group_id);
        let group = TurnClientPathGroup::new(vec![path_a, path_b]).unwrap();

        // First establish that the slot is failed; then make the replacement
        // fail immediately so its watcher must publish the unhealthy state.
        drop(downlink_b);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while group.failed_path_ids() != vec![1] {
                tokio::task::yield_now().await;
            }
        }).await.unwrap();

        let (replacement, _replacement_uplink, replacement_downlink) = mock_path(1, group_id);
        drop(replacement_downlink);
        group.replace_path(replacement).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while group.failed_path_ids() != vec![1] {
                tokio::task::yield_now().await;
            }
        }).await.unwrap();
        assert_eq!(group.active_paths(), 1);
    }

    #[tokio::test]
    async fn simultaneous_path_failures_can_all_be_replaced_in_place() {
        let group_id = [0x7d; 16];
        let (path_a, _uplink_a, downlink_a) = mock_path(0, group_id);
        let (path_b, _uplink_b, downlink_b) = mock_path(1, group_id);
        let group = TurnClientPathGroup::new(vec![path_a, path_b]).unwrap();

        // Both independent allocations fail before either replacement starts.
        drop(downlink_a);
        drop(downlink_b);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while group.failed_path_ids() != vec![0, 1] {
                tokio::task::yield_now().await;
            }
        }).await.unwrap();
        assert_eq!(group.active_paths(), 0);

        let (replacement_a, mut replacement_uplink_a, _replacement_downlink_a) =
            mock_path(0, group_id);
        let (replacement_b, mut replacement_uplink_b, _replacement_downlink_b) =
            mock_path(1, group_id);
        group.replace_path(replacement_a).unwrap();
        group.replace_path(replacement_b).unwrap();

        assert_eq!(group.active_paths(), 2);
        assert!(group.failed_path_ids().is_empty());

        let mut selected_paths = [false, false];
        for source_port in 10000..10002 {
            let datagram = DataDatagram {
                kind: ghulakh_protocol::IpPacketKind::Ipv4,
                packet: packet(source_port),
            };
            group.send_packet(datagram.clone()).await.unwrap();
            let (path_index, received) = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                async {
                    loop {
                        if let Ok(received) = replacement_uplink_a.try_recv() {
                            break (0, received);
                        }
                        if let Ok(received) = replacement_uplink_b.try_recv() {
                            break (1, received);
                        }
                        tokio::task::yield_now().await;
                    }
                },
            ).await.unwrap();
            assert_eq!(received, datagram);
            selected_paths[path_index] = true;
        }
        assert!(selected_paths.into_iter().all(|selected| selected));
        group.close();
    }

    #[tokio::test]
    async fn all_failed_paths_drop_uplink_without_closing_tun_sender() {
        let group_id = [0x7c; 16];
        let (path_a, _uplink_a, downlink_a) = mock_path(0, group_id);
        let (path_b, _uplink_b, downlink_b) = mock_path(1, group_id);
        let group = TurnClientPathGroup::new(vec![path_a, path_b]).unwrap();
        drop(downlink_a);
        drop(downlink_b);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while group.active_paths() != 0 {
                tokio::task::yield_now().await;
            }
        }).await.unwrap();

        let datagram = DataDatagram {
            kind: ghulakh_protocol::IpPacketKind::Ipv4,
            packet: packet(24567),
        };
        group.send_packet(datagram).await.unwrap();
        assert_eq!(group.uplink_queue_drops(), 1);
        assert_eq!(group.failed_path_ids(), vec![0, 1]);
        group.close();
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
        mpsc::Sender<SequencedDataDatagram>,
    ) {
        let (uplink, uplink_rx) = mpsc::channel(APP_QUEUE_CAPACITY);
        let (downlink_tx, downlink) = mpsc::channel(APP_QUEUE_CAPACITY);
        let pending_dataplane = tokio::spawn(async {
            std::future::pending::<Result<TurnDataPlaneStats>>().await
        });
        let (shutdown_signal, mut shutdown_rx) = watch::channel(false);
        let pending_maintenance = tokio::spawn(async move {
            let _ = shutdown_rx.changed().await;
            Ok(())
        });
        (
            TurnClientRuntime {
                config: ghulakh_protocol::session_handshake::TurnSessionConfig {
                    virtual_ipv4: "10.77.0.2".parse().unwrap(),
                    virtual_ipv6: "fd77::2".parse().unwrap(),
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
                shutdown_signal,
            },
            uplink_rx,
            downlink_tx,
        )
    }

    #[test]
    fn downlink_reorder_buffer_restores_sequence_across_paths() {
        let now = Instant::now();
        let mut buffer = DownlinkReorderBuffer::default();
        let make_datagram = |port| DataDatagram {
            kind: ghulakh_protocol::IpPacketKind::Ipv4,
            packet: packet(port),
        };
        buffer.push(SequencedDataDatagram::new(2, make_datagram(12002)), now);
        buffer.push(SequencedDataDatagram::new(0, make_datagram(12000)), now);
        buffer.push(SequencedDataDatagram::new(1, make_datagram(12001)), now);
        assert_eq!(buffer.pop_ready().unwrap().packet[20..22], 12000u16.to_be_bytes());
        assert_eq!(buffer.pop_ready().unwrap().packet[20..22], 12001u16.to_be_bytes());
        assert_eq!(buffer.pop_ready().unwrap().packet[20..22], 12002u16.to_be_bytes());
        assert!(buffer.pop_ready().is_none());
    }

    #[test]
    fn downlink_reorder_buffer_skips_lost_sequence_and_drops_late_packet() {
        let now = Instant::now();
        let mut buffer = DownlinkReorderBuffer::default();
        let make_datagram = |port| DataDatagram {
            kind: ghulakh_protocol::IpPacketKind::Ipv4,
            packet: packet(port),
        };
        buffer.push(SequencedDataDatagram::new(1, make_datagram(12001)), now);
        buffer.push(SequencedDataDatagram::new(3, make_datagram(12003)), now);
        assert!(buffer.pop_ready().is_none());
        let first_gap_deadline = now + DOWNLINK_REORDER_GAP_TIMEOUT;
        buffer.advance_gap(first_gap_deadline);
        assert_eq!(buffer.pop_ready().unwrap().packet[20..22], 12001u16.to_be_bytes());
        assert_eq!(
            buffer.gap_deadline(),
            Some(first_gap_deadline + DOWNLINK_REORDER_GAP_TIMEOUT),
        );
        buffer.advance_gap(first_gap_deadline + DOWNLINK_REORDER_GAP_TIMEOUT);
        assert_eq!(buffer.pop_ready().unwrap().packet[20..22], 12003u16.to_be_bytes());
        buffer.push(SequencedDataDatagram::new(0, make_datagram(12000)), first_gap_deadline);
        buffer.push(SequencedDataDatagram::new(2, make_datagram(12002)), first_gap_deadline);
        assert!(buffer.pop_ready().is_none());
    }

    #[tokio::test]
    async fn path_group_dispatches_merges_downlink_and_degrades_after_path_loss() {
        let group_id = [0x5a; 16];
        let (path_a, mut uplink_a, downlink_a) = mock_path(0, group_id);
        let (path_b, mut uplink_b, downlink_b) = mock_path(1, group_id);
        let group = TurnClientPathGroup::new(vec![path_a, path_b]).unwrap();
        assert_eq!(group.active_paths(), 2);

        // Distinct small UDP flows are spread over the independent path queues.
        let mut selected_paths = [false; 2];
        for source_port in 10000..10100 {
            let datagram = DataDatagram {
                kind: ghulakh_protocol::IpPacketKind::Ipv4,
                packet: packet(source_port),
            };
            group.send_packet(datagram.clone()).await.unwrap();
            if let Ok(received) = uplink_a.try_recv() {
                assert_eq!(received, datagram);
                selected_paths[0] = true;
            } else if let Ok(received) = uplink_b.try_recv() {
                assert_eq!(received, datagram);
                selected_paths[1] = true;
            }
            if selected_paths.iter().all(|selected| *selected) {
                break;
            }
        }
        assert!(selected_paths.into_iter().all(|selected| selected));

        // Sequenced packets arriving on independent paths are resequenced before TUN delivery.
        let ordered_a = DataDatagram {
            kind: ghulakh_protocol::IpPacketKind::Ipv4,
            packet: packet(13000),
        };
        let ordered_b = DataDatagram {
            kind: ghulakh_protocol::IpPacketKind::Ipv4,
            packet: packet(13001),
        };
        downlink_a.send(SequencedDataDatagram::new(1, ordered_b.clone())).await.unwrap();
        downlink_b.send(SequencedDataDatagram::new(0, ordered_a.clone())).await.unwrap();
        assert_eq!(group.receive_packet().await.unwrap(), ordered_a);
        assert_eq!(group.receive_packet().await.unwrap(), ordered_b);

        // The downlink fan-in accepts packets from either independent path.
        let down_a = DataDatagram {
            kind: ghulakh_protocol::IpPacketKind::Ipv4,
            packet: packet(12001),
        };
        let down_b = DataDatagram {
            kind: ghulakh_protocol::IpPacketKind::Ipv4,
            packet: packet(12002),
        };
        downlink_a.send(SequencedDataDatagram::unsequenced(down_a.clone())).await.unwrap();
        downlink_b.send(SequencedDataDatagram::unsequenced(down_b.clone())).await.unwrap();
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

        let datagram = DataDatagram {
            kind: ghulakh_protocol::IpPacketKind::Ipv4,
            packet: packet(20000),
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

        let datagram = DataDatagram {
            kind: ghulakh_protocol::IpPacketKind::Ipv4,
            packet: packet(23456),
        };

        // The source scheduler changes paths at a flowlet boundary when the
        // current allocation's bounded outbound queue is full.
        for _ in 0..(APP_QUEUE_CAPACITY * 2) {
            group.send_packet(datagram.clone()).await.unwrap();
        }
        assert_eq!(group.uplink_queue_drops(), 0);
        assert_eq!(uplink_a.len(), APP_QUEUE_CAPACITY);
        assert_eq!(uplink_b.len(), APP_QUEUE_CAPACITY);

        // Once every path queue is full, the newest packet is dropped.
        group.send_packet(datagram.clone()).await.unwrap();
        assert_eq!(group.uplink_queue_drops(), 1);

        for _ in 0..APP_QUEUE_CAPACITY {
            assert_eq!(uplink_a.recv().await.unwrap(), datagram);
            assert_eq!(uplink_b.recv().await.unwrap(), datagram);
        }
        assert!(uplink_a.try_recv().is_err());
        assert!(uplink_b.try_recv().is_err());
        group.close();
    }

}