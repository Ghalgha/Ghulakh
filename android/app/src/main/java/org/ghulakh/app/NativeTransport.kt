package org.ghulakh.app

/**
 * JNI facade for the native protected TURN VPN runtime.
 * Blocking calls must run on a dedicated worker thread.
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

    /** Returns path identifiers whose authenticated TURN dataplane has failed. */
    external fun nativeTurnFailedPaths(session: Long): IntArray

    /** Recreates one failed path using a fresh protected socket and TURN allocation. */
    external fun nativeTurnRecoverPath(
        vpnService: android.net.VpnService,
        session: Long,
        gatewayHost: String,
        gatewayPort: Int,
        turnCredentialsJson: String,
        pinnedServerKey: ByteArray,
        credential: String,
        pathId: Int,
    ): Boolean


    companion object {
        init {
            System.loadLibrary("ghulakh_transport")
        }
    }
}
