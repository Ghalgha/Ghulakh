//! JNI boundary for the Android application. No credentials are logged.
#![allow(non_snake_case)]

use crate::{ClientOptions, QuicClient};
use anyhow::{Context, Result};
use ghulakh_protocol::{DataDatagram, IpPacketKind};
use jni::{
    objects::{JByteArray, JObject, JString, JValue},
    sys::{jboolean, jbyteArray, jint, jlong, jstring},
    JNIEnv,
};
use rand::{rngs::OsRng, RngCore};
use std::{
    collections::HashMap,
    net::{SocketAddr, UdpSocket},
    sync::{Arc, Mutex, OnceLock},
};
use tokio::runtime::{Builder, Runtime};
#[cfg(target_os = "android")]
use std::os::fd::AsRawFd;

struct NativeSession {
    // Keep the runtime alive until after the QUIC client is dropped.
    client: QuicClient,
    runtime: Runtime,
}

static SESSIONS: OnceLock<Mutex<HashMap<jlong, Arc<NativeSession>>>> = OnceLock::new();

fn sessions() -> &'static Mutex<HashMap<jlong, Arc<NativeSession>>> {
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
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
