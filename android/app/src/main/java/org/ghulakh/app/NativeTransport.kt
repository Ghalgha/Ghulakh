package org.ghulakh.app

/**
 * Thin JNI facade over the shared Rust QUIC transport.
 *
 * Call blocking methods from Dispatchers.IO or a dedicated worker thread.
 * rootCertificateDer must contain the trusted CA/server certificate in DER form.
 */
class NativeTransport {
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
