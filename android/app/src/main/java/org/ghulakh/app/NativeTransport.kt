package org.ghulakh.app

/**
 * JNI facade for the native protected TURN VPN runtime and temporary legacy
 * QUIC diagnostics. Blocking calls must run on a dedicated worker thread.
 */
class NativeTransport {
    external fun nativeTurnConnect(
        vpnService: android.net.VpnService,
        gatewayHost: String,
        gatewayPort: Int,
        turnCredentialsJson: String,
        pinnedServerKey: ByteArray,
        credential: String,
        pathCount: Int,
    ): Long

    external fun nativeTurnClientIpv4(session: Long): String

    external fun nativeTurnMtu(session: Long): Int

    external fun nativeTurnSendPacket(session: Long, packet: ByteArray): Boolean

    /** Blocks until an authenticated IPv4 packet arrives or the TURN session fails. */
    external fun nativeTurnReceivePacket(session: Long): ByteArray?

    external fun nativeTurnClose(session: Long)

    external fun nativeConnect(
        vpnService: android.net.VpnService?,
        host: String,
        port: Int,
        serverName: String,
        rootCertificateDer: ByteArray,
        credential: String,
    ): Long

    external fun nativeClientIpv4(session: Long): String

    external fun nativeTunnelEnabled(session: Long): Boolean

    external fun nativeForwardingEnabled(session: Long): Boolean

    external fun nativeSendPacket(session: Long, packet: ByteArray): Boolean

    /** Blocks until a validated IPv4/IPv6 packet arrives or the session fails. */
    external fun nativeReceivePacket(session: Long): ByteArray?

    external fun nativePing(session: Long): Boolean

    external fun nativeClose(session: Long)

    companion object {
        init {
            System.loadLibrary("ghulakh_transport")
        }
    }
}
