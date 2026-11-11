package org.ghulakh.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.util.Log
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.Collections
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Bridges Android's packet TUN to the protected VK Calls TURN dataplane.
 */
class GhulakhVpnService : VpnService() {
    private val running = AtomicBoolean(false)

    @Volatile
    private var tunnelDescriptor: ParcelFileDescriptor? = null

    @Volatile
    private var nativeTransport: NativeTransport? = null

    @Volatile
    private var sessionHandle = 0L

    @Volatile
    private var worker: Thread? = null

    @Volatile
    private var recoveryWorker: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (VpnService.prepare(this) != null) {
            stopSelf()
            return START_NOT_STICKY
        }
        try {
            startForeground(NOTIFICATION_ID, notification("Получение временных credentials VK Calls"))
        } catch (error: Exception) {
            Log.e(TAG, "Unable to start foreground VPN service", error)
            stopSelf()
            return START_NOT_STICKY
        }
        if (running.compareAndSet(false, true)) {
            isActive = true
            worker = Thread({ runTunnel() }, "ghulakh-vpn-session").apply { start() }
        }
        return START_NOT_STICKY
    }

    private fun runTunnel() {
        val vkSessions = Collections.synchronizedList(mutableListOf<VkCallsSession>())
        try {
            val profile = CredentialStore(this).load()
                ?: throw IllegalStateException("Профиль соединения не настроен")
            val callsSession = VkCallsCredentialProvider.obtain(profile.vkAccessToken)
            vkSessions.add(callsSession)
            val transport = NativeTransport()
            nativeTransport = transport

            val handle = transport.nativeTurnConnect(
                this,
                profile.host,
                profile.port,
                callsSession.turnCredentialsJson,
                decodeHexKey(profile.pinnedServerPublicKeyHex),
                profile.credential,
                DEFAULT_TURN_PATHS,
            )
            sessionHandle = handle

            val clientAddress = transport.nativeTurnClientIpv4(handle)
            val mtu = transport.nativeTurnMtu(handle)
            require(mtu in MIN_TUN_MTU..MAX_TUN_MTU) { "Сервер передал недопустимый MTU" }
            val descriptor = Builder()
                .setSession("Ghulakh")
                .setMtu(mtu)
                .addAddress(clientAddress, 32)
                .addAddress("fd77::2", 128)
                .addRoute("0.0.0.0", 0)
                // IPv6 is captured to prevent leaks; the current server drops IPv6 packets.
                .addRoute("::", 0)
                .addDnsServer("1.1.1.1")
                .establish()
                ?: throw IllegalStateException("Android не создал TUN-интерфейс")
            tunnelDescriptor = descriptor
            updateNotification("VPN активен · IPv4 через TURN-реле VK Calls · IPv6 блокируется")

            val input = FileInputStream(descriptor.fileDescriptor)
            val output = FileOutputStream(descriptor.fileDescriptor)

            val tunReader = Thread({
                try {
                    val buffer = ByteArray(MAX_IP_PACKET_SIZE)
                    while (running.get()) {
                        val length = input.read(buffer)
                        if (length < 0) {
                            if (running.get()) {
                                throw IllegalStateException("Android TUN input reached end-of-stream")
                            }
                            break
                        }
                        if (length > 0) {
                            val version = (buffer[0].toInt() and 0xff) ushr 4
                            if (version == 6) continue
                            if (version != 4) {
                                throw IllegalStateException("Android TUN returned an unsupported IP version")
                            }
                            if (!transport.nativeTurnSendPacket(handle, buffer.copyOf(length))) {
                                throw IllegalStateException("TURN-транспорт отклонил IPv4-пакет")
                            }
                        }
                    }
                } catch (error: Throwable) {
                    if (running.get()) failSession("Ошибка чтения Android TUN", error)
                }
            }, "ghulakh-tun-reader")

            val tunWriter = Thread({
                try {
                    while (running.get()) {
                        val packet = transport.nativeTurnReceivePacket(handle)
                            ?: throw IllegalStateException("TURN transport returned an empty packet result")
                        output.write(packet)
                        output.flush()
                    }
                } catch (error: Throwable) {
                    if (running.get()) failSession("Ошибка приёма TURN-пакета", error)
                }
            }, "ghulakh-tun-writer")

            tunReader.start()
            tunWriter.start()
            recoveryWorker = Thread({
                recoverFailedPaths(profile, transport, handle, vkSessions)
            }, "ghulakh-turn-recovery").apply { start() }
            tunReader.join()
            tunWriter.join()
        } catch (error: Throwable) {
            if (running.get()) {
                Log.e(TAG, "VPN session failed", error)
                updateNotification("Ошибка VPN · ${error.message ?: "соединение прервано"}")
            }
        } finally {
            stopTunnel()
            synchronized(vkSessions) {
                vkSessions.forEach { calls ->
                    runCatching { calls.finish() }
                        .onFailure { error -> Log.w(TAG, "Failed to finish VK Calls session", error) }
                }
                vkSessions.clear()
            }
            stopSelf()
        }
    }


    private fun recoverFailedPaths(
        profile: ConnectionProfile,
        transport: NativeTransport,
        handle: Long,
        vkSessions: MutableList<VkCallsSession>,
    ) {
        val failures = mutableMapOf<Int, Int>()
        val nextAttemptAt = mutableMapOf<Int, Long>()
        while (running.get()) {
            val failedPaths = runCatching { transport.nativeTurnFailedPaths(handle).toList() }
                .getOrElse { error ->
                    if (running.get()) Log.w(TAG, "Unable to inspect TURN path health", error)
                    emptyList()
                }
            for (pathId in failedPaths) {
                if (!running.get()) break
                val now = SystemClock.elapsedRealtime()
                if (now < (nextAttemptAt[pathId] ?: 0L)) continue
                var callsSession: VkCallsSession? = null
                try {
                    val establishedSession = VkCallsCredentialProvider.obtain(profile.vkAccessToken)
                    callsSession = establishedSession
                    if (!running.get()) {
                        establishedSession.finish()
                        return
                    }
                    check(transport.nativeTurnRecoverPath(
                        this,
                        handle,
                        profile.host,
                        profile.port,
                        establishedSession.turnCredentialsJson,
                        decodeHexKey(profile.pinnedServerPublicKeyHex),
                        profile.credential,
                        pathId,
                    )) { "Native TURN path replacement was rejected" }
                    val retained = synchronized(vkSessions) {
                        if (running.get()) {
                            vkSessions.add(establishedSession)
                            true
                        } else {
                            false
                        }
                    }
                    if (!retained) {
                        establishedSession.finish()
                        return
                    }
                    callsSession = null
                    failures.remove(pathId)
                    nextAttemptAt.remove(pathId)
                    updateNotification("VPN активен · TURN-путь $pathId восстановлен")
                } catch (error: Throwable) {
                    runCatching { callsSession?.finish() }
                    val count = failures[pathId] ?: 0
                    val delaySeconds = (1L shl count.coerceAtMost(5)).coerceAtMost(30L)
                    failures[pathId] = count + 1
                    nextAttemptAt[pathId] = SystemClock.elapsedRealtime() + delaySeconds * 1_000L
                    if (running.get()) {
                        Log.w(TAG, "TURN path $pathId recovery failed; retry in ${delaySeconds}s", error)
                        updateNotification("VPN активен · восстановление TURN-пути $pathId")
                    }
                }
            }
            try {
                Thread.sleep(1_000)
            } catch (_: InterruptedException) {
                return
            }
        }
    }

    private fun decodeHexKey(value: String): ByteArray {
        require(value.length == 64 && value.all { it in "0123456789abcdefABCDEF" }) {
            "Pinned Noise key must contain exactly 64 hexadecimal characters"
        }
        return ByteArray(32) { index ->
            value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }

    private fun failSession(message: String, error: Throwable) {
        Log.e(TAG, message, error)
        updateNotification("$message: ${error.message ?: "ошибка"}")
        stopTunnel()
        stopSelf()
    }

    @Synchronized
    private fun stopTunnel() {
        running.set(false)
        recoveryWorker?.interrupt()
        recoveryWorker = null
        try {
            tunnelDescriptor?.close()
        } catch (_: Exception) {
        }
        tunnelDescriptor = null

        val handle = sessionHandle
        sessionHandle = 0L
        if (handle != 0L) {
            try {
                nativeTransport?.nativeTurnClose(handle)
            } catch (error: Throwable) {
                Log.w(TAG, "Failed to close native TURN session", error)
            }
        }
        nativeTransport = null
    }

    override fun onRevoke() {
        stopTunnel()
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        isActive = false
        stopTunnel()
        worker?.interrupt()
        stopForeground(STOP_FOREGROUND_REMOVE)
        super.onDestroy()
    }

    private fun notification(message: String): Notification {
        val manager = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    "Ghulakh VPN",
                    NotificationManager.IMPORTANCE_LOW,
                ),
            )
        }
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("Ghulakh")
            .setContentText(message)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(message: String) {
        val manager = getSystemService(NotificationManager::class.java)
        manager.notify(NOTIFICATION_ID, notification(message))
    }

    companion object {
        @Volatile
        var isActive: Boolean = false
            private set

        private const val TAG = "GhulakhVpn"
        private const val CHANNEL_ID = "ghulakh_vpn"
        private const val NOTIFICATION_ID = 7701
        private const val MIN_TUN_MTU = 576
        private const val MAX_TUN_MTU = 1500
        private const val MAX_IP_PACKET_SIZE = 65_535
        private const val DEFAULT_TURN_PATHS = 5
    }
}
