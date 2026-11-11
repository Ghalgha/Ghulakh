//! JNI boundary for the Android application. No credentials are logged.
#![allow(non_snake_case)]

use crate::{
    ClientOptions,
    QuicClient,
    turn_client::{TurnClientPathGroup, TurnClientRuntime},
    turn_credentials::TurnCredentials,
};
use anyhow::{Context, Result};
use ghulakh_protocol::{DataDatagram, IpPacketKind, turn_path_context::{TurnPathContext, MAX_TURN_PATHS}};
use jni::{
    objects::{JByteArray, JObject, JString},
    sys::{jboolean, jbyteArray, jint, jlong, jstring},
    JNIEnv,
};
use rand::{rngs::OsRng, RngCore};
use std::{
    collections::HashMap,
    net::{SocketAddr, UdpSocket},
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};
use tokio::{runtime::{Builder, Runtime}, task::JoinSet};
#[cfg(target_os = "android")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "android")]
use jni::objects::JValue;

struct NativeTurnSession {
    client: TurnClientPathGroup,
    runtime: Runtime,
}

struct NativeSession {
    // Keep the runtime alive until after the QUIC client is dropped.
    client: QuicClient,
    runtime: Runtime,
}

static SESSIONS: OnceLock<Mutex<HashMap<jlong, Arc<NativeSession>>>> = OnceLock::new();

fn sessions() -> &'static Mutex<HashMap<jlong, Arc<NativeSession>>> {
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

static TURN_SESSIONS: OnceLock<Mutex<HashMap<jlong, Arc<NativeTurnSession>>>> = OnceLock::new();

fn turn_sessions() -> &'static Mutex<HashMap<jlong, Arc<NativeTurnSession>>> {
    TURN_SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn turn_session(handle: jlong) -> Result<Arc<NativeTurnSession>> {
    let registry = turn_sessions()
        .lock()
        .map_err(|_| anyhow::anyhow!("native TURN session registry is unavailable"))?;
    registry
        .get(&handle)
        .cloned()
        .context("unknown native TURN session handle")
}

fn session(handle: jlong) -> Result<Arc<NativeSession>> {
    let registry = sessions()
        .lock()
        .map_err(|_| anyhow::anyhow!("native session registry is unavailable"))?;
    registry
        .get(&handle)
        .cloned()
        .context("unknown native session handle")
}


#[cfg(target_os = "android")]
fn make_protected_socket(env: &mut JNIEnv, service: &JObject) -> Result<Option<UdpSocket>> {
    if service.is_null() {
        return Ok(None);
    }
    let socket = UdpSocket::bind("0.0.0.0:0").context("bind protected UDP socket")?;
    socket.set_nonblocking(true).context("set UDP socket nonblocking")?;
    let protected = env
        .call_method(
            service,
            "protect",
            "(I)Z",
            &[JValue::Int(socket.as_raw_fd())],
        )?
        .z()?;
    anyhow::ensure!(protected, "Android VpnService refused to protect QUIC socket");
    Ok(Some(socket))
}

#[cfg(not(target_os = "android"))]
fn make_protected_socket(_env: &mut JNIEnv, service: &JObject) -> Result<Option<UdpSocket>> {
    anyhow::ensure!(
        service.is_null(),
        "VpnService socket protection is only available on Android"
    );
    Ok(None)
}

fn connect_impl(
    env: &mut JNIEnv,
    vpn_service: JObject,
    host: JString,
    port: jint,
    server_name: JString,
    root_certificate_der: JByteArray,
    credential: JString,
) -> Result<jlong> {
    let host = env.get_string(&host)?.to_string_lossy().into_owned();
    let server_name = env
        .get_string(&server_name)?
        .to_string_lossy()
        .into_owned();
    let credential = env.get_string(&credential)?.to_string_lossy().into_owned();
    let root_certificate_der = env.convert_byte_array(root_certificate_der)?;

    let port = u16::try_from(port).context("server port is invalid")?;
    anyhow::ensure!(port != 0, "server port must not be zero");

    let udp_socket = make_protected_socket(env, &vpn_service)?;
    let runtime = Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("create native Tokio runtime")?;
    let server_addr: SocketAddr = runtime.block_on(async {
        let mut addresses = tokio::net::lookup_host((host.as_str(), port)).await?;
        let address = if udp_socket.is_some() {
            addresses.find(SocketAddr::is_ipv4)
        } else {
            addresses.next()
        };
        address.context("server host did not resolve to a supported address")
    })?;
    let client = runtime.block_on(QuicClient::connect(ClientOptions {
        server_addr,
        server_name,
        root_certificate_der,
        credential,
        udp_socket,
    }))?;

    let native_session = Arc::new(NativeSession { client, runtime });
    let mut registry = sessions()
        .lock()
        .map_err(|_| anyhow::anyhow!("native session registry is unavailable"))?;
    let handle = loop {
        let mut bytes = [0u8; 8];
        OsRng.fill_bytes(&mut bytes);
        let candidate = (u64::from_be_bytes(bytes) & i64::MAX as u64) as jlong;
        if candidate != 0 && !registry.contains_key(&candidate) {
            break candidate;
        }
    };
    let _previous = registry.insert(handle, native_session);
    Ok(handle)
}


struct TurnConnectArgs<'local> {
    vpn_service: JObject<'local>,
    gateway_host: JString<'local>,
    gateway_port: jint,
    turn_credentials_json: JString<'local>,
    pinned_server_key: JByteArray<'local>,
    credential: JString<'local>,
    path_count: jint,
}

fn connect_turn_impl(
    env: &mut JNIEnv,
    args: TurnConnectArgs<'_>,
) -> Result<jlong> {
    let TurnConnectArgs {
        vpn_service,
        gateway_host,
        gateway_port,
        turn_credentials_json,
        pinned_server_key,
        credential,
        path_count,
    } = args;
    let gateway_host = env.get_string(&gateway_host)?.to_string_lossy().into_owned();
    let turn_credentials_json = env
        .get_string(&turn_credentials_json)?
        .to_string_lossy()
        .into_owned();
    let credential = env.get_string(&credential)?.to_string_lossy().into_owned();
    let pinned_server_key = env.convert_byte_array(pinned_server_key)?;
    anyhow::ensure!(pinned_server_key.len() == 32, "pinned Noise server key must be 32 bytes");
    anyhow::ensure!(
        !credential.is_empty() && credential.len() <= ghulakh_protocol::MAX_CREDENTIAL_LEN,
        "tunnel credential length is invalid"
    );
    let path_count = u16::try_from(path_count).context("TURN path count is invalid")?;
    anyhow::ensure!(
        (2..=MAX_TURN_PATHS).contains(&path_count),
        "TURN path count must be between 2 and 10"
    );
    let gateway_port = u16::try_from(gateway_port).context("TURN gateway port is invalid")?;
    anyhow::ensure!(gateway_port != 0, "TURN gateway port must not be zero");
    anyhow::ensure!(!gateway_host.trim().is_empty(), "TURN gateway host is empty");

    // Each path owns a separate Android-protected UDP socket and TURN allocation.
    let mut protected_sockets = Vec::with_capacity(usize::from(path_count));
    for _ in 0..path_count {
        protected_sockets.push(
            make_protected_socket(env, &vpn_service)?
                .context("Android protected TURN UDP socket is required")?,
        );
    }

    let runtime = Builder::new_multi_thread()
        .worker_threads(usize::from(path_count).clamp(2, 10))
        .enable_all()
        .build()
        .context("create multipath TURN Tokio runtime")?;
    let gateway_addr: SocketAddr = runtime.block_on(async {
        let mut addresses = tokio::net::lookup_host((gateway_host.as_str(), gateway_port)).await?;
        addresses
            .find(SocketAddr::is_ipv4)
            .context("TURN gateway host did not resolve to IPv4")
    })?;

    let mut group_id = [0u8; 16];
    OsRng.fill_bytes(&mut group_id);
    anyhow::ensure!(group_id.iter().any(|byte| *byte != 0), "invalid random TURN group ID");

    let clients = runtime.block_on(async {
        let mut tasks = JoinSet::new();
        for (path_id, protected_socket) in protected_sockets.into_iter().enumerate() {
            let credentials = TurnCredentials::from_vk_response_json(&turn_credentials_json)
                .context("parse temporary VK Calls TURN credentials")?;
            let pinned_key = pinned_server_key.clone();
            let tunnel_credential = credential.as_bytes().to_vec();
            let context = TurnPathContext {
                group_id,
                path_id: path_id as u16,
                path_count,
            };
            tasks.spawn(async move {
                TurnClientRuntime::connect_with_path_context(
                    protected_socket,
                    credentials,
                    gateway_addr,
                    &pinned_key,
                    &tunnel_credential,
                    context,
                ).await
            });

            // Stagger independent TURN allocations to avoid a synchronized
            // burst against the relay service. This is startup pacing only;
            // it does not serialize the established data paths.
            if path_id + 1 < usize::from(path_count) {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }

        let mut clients = Vec::with_capacity(usize::from(path_count));
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(Ok(client)) => clients.push(client),
                Ok(Err(error)) => {
                    tasks.abort_all();
                    for client in &clients {
                        client.close();
                    }
                    return Err(error).context("establish one of the TURN paths");
                }
                Err(error) => {
                    tasks.abort_all();
                    for client in &clients {
                        client.close();
                    }
                    return Err(anyhow::anyhow!(error)).context("TURN path task failed");
                }
            }
        }
        TurnClientPathGroup::new(clients)
            .context("assemble authenticated TURN path group")
    })?;

    let native_session = Arc::new(NativeTurnSession { client: clients, runtime });
    let mut registry = turn_sessions()
        .lock()
        .map_err(|_| anyhow::anyhow!("native TURN session registry is unavailable"))?;
    let handle = loop {
        let mut bytes = [0u8; 8];
        OsRng.fill_bytes(&mut bytes);
        let candidate = (u64::from_be_bytes(bytes) & i64::MAX as u64) as jlong;
        if candidate != 0 && !registry.contains_key(&candidate) {
            break candidate;
        }
    };
    registry.insert(handle, native_session);
    Ok(handle)
}


fn failed_turn_paths_impl(handle: jlong) -> Result<Vec<jint>> {
    Ok(turn_session(handle)?.client.failed_path_ids().into_iter().map(jint::from).collect())
}


struct TurnRecoverArgs<'local> {
    vpn_service: JObject<'local>,
    handle: jlong,
    gateway_host: JString<'local>,
    gateway_port: jint,
    turn_credentials_json: JString<'local>,
    pinned_server_key: JByteArray<'local>,
    credential: JString<'local>,
    path_id: jint,
}

fn recover_turn_path_impl(env: &mut JNIEnv, args: TurnRecoverArgs<'_>) -> Result<()> {
    let TurnRecoverArgs {
        vpn_service, handle, gateway_host, gateway_port, turn_credentials_json,
        pinned_server_key, credential, path_id,
    } = args;
    let host = env.get_string(&gateway_host)?.to_string_lossy().into_owned();
    let credentials_json = env.get_string(&turn_credentials_json)?.to_string_lossy().into_owned();
    let credential = env.get_string(&credential)?.to_string_lossy().into_owned();
    let pinned_key = env.convert_byte_array(pinned_server_key)?;
    anyhow::ensure!(pinned_key.len() == 32, "pinned Noise server key must be 32 bytes");
    anyhow::ensure!(!credential.is_empty() && credential.len() <= ghulakh_protocol::MAX_CREDENTIAL_LEN,
        "tunnel credential length is invalid");
    let port = u16::try_from(gateway_port).context("TURN gateway port is invalid")?;
    anyhow::ensure!(port != 0 && !host.trim().is_empty(), "TURN gateway endpoint is invalid");
    let path_id = u16::try_from(path_id).context("TURN path identifier is invalid")?;
    let session = turn_session(handle)?;
    let context = session.client.path_context(path_id).context("unknown TURN path slot")?;
    anyhow::ensure!(session.client.failed_path_ids().contains(&path_id), "TURN path is still healthy");
    let socket = make_protected_socket(env, &vpn_service)?
        .context("Android protected TURN UDP socket is required")?;
    let credentials = TurnCredentials::from_vk_response_json(&credentials_json)
        .context("parse refreshed VK Calls TURN credentials")?;
    let gateway: SocketAddr = session.runtime.block_on(async {
        let mut addresses = tokio::net::lookup_host((host.as_str(), port)).await?;
        addresses.find(SocketAddr::is_ipv4).context("TURN gateway host did not resolve to IPv4")
    })?;
    let replacement = session.runtime.block_on(TurnClientRuntime::connect_with_path_context(
        socket, credentials, gateway, &pinned_key, credential.as_bytes(), context,
    )).context("establish replacement TURN allocation")?;
    session.client.replace_path(replacement).context("install replacement TURN path")
}

fn send_turn_packet_impl(env: &mut JNIEnv, handle: jlong, packet: JByteArray) -> Result<()> {
    let packet = env.convert_byte_array(packet)?;
    let first_byte = *packet.first().context("IP packet is empty")?;
    let kind = IpPacketKind::try_from(first_byte >> 4)?;
    let session = turn_session(handle)?;
    session.runtime.block_on(session.client.send_packet(DataDatagram { kind, packet }))
}

fn receive_turn_packet_impl(handle: jlong) -> Result<Vec<u8>> {
    let session = turn_session(handle)?;
    session.runtime.block_on(async {
        let packet = session.client.receive_packet().await?;
        Ok::<Vec<u8>, anyhow::Error>(packet.packet)
    })
}

fn turn_client_config_impl(handle: jlong) -> Result<(String, jint)> {
    let session = turn_session(handle)?;
    let config = session.client.config();
    Ok((config.virtual_ipv4.to_string(), jint::from(config.mtu)))
}

fn close_turn_impl(handle: jlong) -> Result<()> {
    let session = {
        let mut registry = turn_sessions()
            .lock()
            .map_err(|_| anyhow::anyhow!("native TURN session registry is unavailable"))?;
        registry.remove(&handle)
    }
    .context("unknown native TURN session handle")?;
    session.client.close();
    Ok(())
}

fn send_packet_impl(env: &mut JNIEnv, handle: jlong, packet: JByteArray) -> Result<()> {
    let packet = env.convert_byte_array(packet)?;
    let first_byte = *packet.first().context("IP packet is empty")?;
    let kind = IpPacketKind::try_from(first_byte >> 4)?;
    let session = session(handle)?;
    let datagram = DataDatagram { kind, packet };
    session.runtime.block_on(session.client.send_packet(&datagram))
}

fn receive_packet_impl(handle: jlong) -> Result<Vec<u8>> {
    let session = session(handle)?;
    session.runtime.block_on(async {
        let packet = session.client.receive_packet().await?;
        Ok::<Vec<u8>, anyhow::Error>(packet.packet)
    })
}

fn client_ipv4_impl(handle: jlong) -> Result<String> {
    let session = session(handle)?;
    Ok(session.client.client_ipv4().to_owned())
}

fn tunnel_enabled_impl(handle: jlong) -> Result<bool> {
    let session = session(handle)?;
    Ok(session.client.tunnel_enabled())
}

fn forwarding_enabled_impl(handle: jlong) -> Result<bool> {
    let session = session(handle)?;
    Ok(session.client.forwarding_enabled())
}

fn ping_impl(handle: jlong) -> Result<()> {
    let session = session(handle)?;
    session.runtime.block_on(session.client.ping())
}

fn close_impl(handle: jlong) -> Result<()> {
    let session = {
        let mut registry = sessions()
            .lock()
            .map_err(|_| anyhow::anyhow!("native session registry is unavailable"))?;
        registry.remove(&handle)
    }
    .context("unknown native session handle")?;
    session.client.close();
    Ok(())
}

fn throw_error(env: &mut JNIEnv, class: &str, error: impl std::fmt::Display) {
    let _ = env.throw_new(class, error.to_string());
}


#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub extern "system" fn Java_org_ghulakh_app_NativeTransport_nativeTurnConnect(
    mut env: JNIEnv,
    _this: JObject,
    vpn_service: JObject,
    gateway_host: JString,
    gateway_port: jint,
    turn_credentials_json: JString,
    pinned_server_key: JByteArray,
    credential: JString,
    path_count: jint,
) -> jlong {
    match connect_turn_impl(
        &mut env,
        TurnConnectArgs {
            vpn_service,
            gateway_host,
            gateway_port,
            turn_credentials_json,
            pinned_server_key,
            credential,
            path_count,
        },
    ) {
        Ok(handle) => handle,
        Err(error) => {
            throw_error(&mut env, "java/lang/IllegalStateException", error);
            0
        }
    }
}


#[no_mangle]
pub extern "system" fn Java_org_ghulakh_app_NativeTransport_nativeTurnFailedPaths(
    mut env: JNIEnv, _this: JObject, handle: jlong,
) -> jni::sys::jintArray {
    match failed_turn_paths_impl(handle) {
        Ok(paths) => match env.new_int_array(paths.len() as jint) {
            Ok(array) => {
                if let Err(error) = env.set_int_array_region(&array, 0, &paths) {
                    throw_error(&mut env, "java/lang/IllegalStateException", error);
                    return std::ptr::null_mut();
                }
                array.into_raw()
            }
            Err(error) => { throw_error(&mut env, "java/lang/IllegalStateException", error); std::ptr::null_mut() }
        },
        Err(error) => { throw_error(&mut env, "java/lang/IllegalStateException", error); std::ptr::null_mut() }
    }
}

#[no_mangle]
pub extern "system" fn Java_org_ghulakh_app_NativeTransport_nativeTurnRecoverPath(
    mut env: JNIEnv, _this: JObject, service: JObject, handle: jlong,
    host: JString, port: jint, credentials: JString, pinned_key: JByteArray,
    credential: JString, path_id: jint,
) -> jboolean {
    match recover_turn_path_impl(&mut env, TurnRecoverArgs {
        vpn_service: service, handle, gateway_host: host, gateway_port: port,
        turn_credentials_json: credentials, pinned_server_key: pinned_key,
        credential, path_id,
    }) {
        Ok(()) => 1,
        Err(error) => { throw_error(&mut env, "java/lang/IllegalStateException", error); 0 }
    }
}

#[no_mangle]
pub extern "system" fn Java_org_ghulakh_app_NativeTransport_nativeTurnSendPacket(
    mut env: JNIEnv,
    _this: JObject,
    handle: jlong,
    packet: JByteArray,
) -> jboolean {
    match send_turn_packet_impl(&mut env, handle, packet) {
        Ok(()) => 1,
        Err(error) => {
            throw_error(&mut env, "java/lang/IllegalStateException", error);
            0
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_org_ghulakh_app_NativeTransport_nativeTurnReceivePacket(
    mut env: JNIEnv,
    _this: JObject,
    handle: jlong,
) -> jbyteArray {
    match receive_turn_packet_impl(handle) {
        Ok(packet) => match env.byte_array_from_slice(&packet) {
            Ok(array) => array.into_raw(),
            Err(error) => {
                throw_error(&mut env, "java/lang/IllegalStateException", error);
                std::ptr::null_mut()
            }
        },
        Err(error) => {
            throw_error(&mut env, "java/lang/IllegalStateException", error);
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_org_ghulakh_app_NativeTransport_nativeTurnClientIpv4(
    mut env: JNIEnv,
    _this: JObject,
    handle: jlong,
) -> jstring {
    match turn_client_config_impl(handle) {
        Ok((address, _)) => match env.new_string(address) {
            Ok(value) => value.into_raw(),
            Err(error) => {
                throw_error(&mut env, "java/lang/IllegalStateException", error);
                std::ptr::null_mut()
            }
        },
        Err(error) => {
            throw_error(&mut env, "java/lang/IllegalStateException", error);
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_org_ghulakh_app_NativeTransport_nativeTurnMtu(
    mut env: JNIEnv,
    _this: JObject,
    handle: jlong,
) -> jint {
    match turn_client_config_impl(handle) {
        Ok((_, mtu)) => mtu,
        Err(error) => {
            throw_error(&mut env, "java/lang/IllegalStateException", error);
            0
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_org_ghulakh_app_NativeTransport_nativeTurnClose(
    mut env: JNIEnv,
    _this: JObject,
    handle: jlong,
) {
    if let Err(error) = close_turn_impl(handle) {
        throw_error(&mut env, "java/lang/IllegalStateException", error);
    }
}

#[no_mangle]
pub extern "system" fn Java_org_ghulakh_app_NativeTransport_nativeConnect(
    mut env: JNIEnv,
    _this: JObject,
    vpn_service: JObject,
    host: JString,
    port: jint,
    server_name: JString,
    root_certificate_der: JByteArray,
    credential: JString,
) -> jlong {
    match connect_impl(
        &mut env,
        vpn_service,
        host,
        port,
        server_name,
        root_certificate_der,
        credential,
    ) {
        Ok(handle) => handle,
        Err(error) => {
            throw_error(&mut env, "java/lang/IllegalStateException", error);
            0
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_org_ghulakh_app_NativeTransport_nativeSendPacket(
    mut env: JNIEnv,
    _this: JObject,
    handle: jlong,
    packet: JByteArray,
) -> jboolean {
    match send_packet_impl(&mut env, handle, packet) {
        Ok(()) => 1,
        Err(error) => {
            throw_error(&mut env, "java/lang/IllegalStateException", error);
            0
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_org_ghulakh_app_NativeTransport_nativeReceivePacket(
    mut env: JNIEnv,
    _this: JObject,
    handle: jlong,
) -> jbyteArray {
    match receive_packet_impl(handle) {
        Ok(packet) => match env.byte_array_from_slice(&packet) {
            Ok(array) => array.into_raw(),
            Err(error) => {
                throw_error(&mut env, "java/lang/IllegalStateException", error);
                std::ptr::null_mut()
            }
        },
        Err(error) => {
            throw_error(&mut env, "java/lang/IllegalStateException", error);
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_org_ghulakh_app_NativeTransport_nativePing(
    mut env: JNIEnv,
    _this: JObject,
    handle: jlong,
) -> jboolean {
    match ping_impl(handle) {
        Ok(()) => 1,
        Err(error) => {
            throw_error(&mut env, "java/lang/IllegalStateException", error);
            0
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_org_ghulakh_app_NativeTransport_nativeClose(
    mut env: JNIEnv,
    _this: JObject,
    handle: jlong,
) {
    if let Err(error) = close_impl(handle) {
        throw_error(&mut env, "java/lang/IllegalStateException", error);
    }
}

#[no_mangle]
pub extern "system" fn Java_org_ghulakh_app_NativeTransport_nativeClientIpv4(
    mut env: JNIEnv,
    _this: JObject,
    handle: jlong,
) -> jstring {
    match client_ipv4_impl(handle) {
        Ok(address) => match env.new_string(address) {
            Ok(value) => value.into_raw(),
            Err(error) => {
                throw_error(&mut env, "java/lang/IllegalStateException", error);
                std::ptr::null_mut()
            }
        },
        Err(error) => {
            throw_error(&mut env, "java/lang/IllegalStateException", error);
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_org_ghulakh_app_NativeTransport_nativeTunnelEnabled(
    mut env: JNIEnv,
    _this: JObject,
    handle: jlong,
) -> jboolean {
    match tunnel_enabled_impl(handle) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(error) => {
            throw_error(&mut env, "java/lang/IllegalStateException", error);
            0
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_org_ghulakh_app_NativeTransport_nativeForwardingEnabled(
    mut env: JNIEnv,
    _this: JObject,
    handle: jlong,
) -> jboolean {
    match forwarding_enabled_impl(handle) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(error) => {
            throw_error(&mut env, "java/lang/IllegalStateException", error);
            0
        }
    }
}
