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
import java.util.concurrent.ConcurrentHashMap
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

    private val recoveryLock = Any()
    private val recoveryTokens = mutableSetOf<AtomicBoolean>()
    private val pathRecoveryThreads = mutableMapOf<Int, Thread>()

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
            val transport = NativeTransport()
            val rejectedCredentialFingerprints = mutableSetOf<String>()
            var connectAttempt = 0
            var callsSession: VkCallsCredentialGroup? = null
            var handle = 0L
            while (true) {
                if (!running.get()) return
                val candidate = VkCallsCredentialProvider.obtainGroup(profile.vkAccessToken, DEFAULT_TURN_PATHS)
                try {
                    val connectedHandle = transport.nativeTurnConnect(
                        this,
                        profile.host,
                        profile.port,
                        candidate.turnCredentialsJson,
                        decodeHexKey(profile.pinnedServerPublicKeyHex),
                        profile.credential,
                        DEFAULT_TURN_PATHS,
                    )
                    handle = connectedHandle
                    callsSession = candidate
                    break
                } catch (error: Throwable) {
                    candidate.finish()
                    if (error.message != "TURN_ALLOCATION_QUOTA_486" ||
                        !TurnQuotaRetryPolicy.shouldRetryGroup(
                            connectAttempt,
                            candidate.turnCredentialsJson,
                            rejectedCredentialFingerprints,
                        )
                    ) {
                        throw error
                    }
                    connectAttempt++
                    if (!running.get()) return
                    Thread.sleep(TurnQuotaRetryPolicy.retryDelayMillis(connectAttempt - 1))
                }
            }
            val establishedGroup = checkNotNull(callsSession)
            vkSessions.add(establishedGroup.ownerSession)
            val retained = synchronized(this) {
                if (running.get()) {
                    nativeTransport = transport
                    sessionHandle = handle
                    true
                } else {
                    false
                }
            }
            if (!retained) {
                transport.nativeTurnClose(handle)
                return
            }

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
            val recoveryToken = AtomicBoolean(running.get())
            synchronized(recoveryLock) {
                if (running.get()) recoveryTokens.add(recoveryToken) else recoveryToken.set(false)
            }
            recoveryWorker = Thread({
                recoverFailedPaths(
                    profile,
                    transport,
                    handle,
                    establishedGroup.credentialBroker,
                    recoveryToken,
                )
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
        credentialBroker: VkCallsCredentialProvider.CredentialBroker,
        recoveryToken: AtomicBoolean,
    ) {
        val failures = ConcurrentHashMap<Int, Int>()
        val nextAttemptAt = ConcurrentHashMap<Int, Long>()
        val rejectedCredentials = linkedSetOf<String>()
        try {
            while (running.get() && recoveryToken.get()) {
                val failedPaths = runCatching { transport.nativeTurnFailedPaths(handle).toList() }
                    .getOrElse { error ->
                        if (running.get() && recoveryToken.get()) {
                            Log.w(TAG, "Unable to inspect TURN path health", error)
                        }
                        emptyList()
                    }
                for (pathId in failedPaths) {
                    if (!running.get() || !recoveryToken.get()) break
                    val now = SystemClock.elapsedRealtime()
                    val recoveryThread = synchronized(recoveryLock) {
                        if (!running.get() || !recoveryToken.get() ||
                            pathRecoveryThreads.containsKey(pathId) ||
                            now < (nextAttemptAt[pathId] ?: 0L)
                        ) {
                            null
                        } else {
                            Thread({
                                recoverPath(
                                    pathId,
                                    profile,
                                    transport,
                                    handle,
                                    credentialBroker,
                                    failures,
                                    nextAttemptAt,
                                    rejectedCredentials,
                                    recoveryToken,
                                )
                            }, "ghulakh-turn-recovery-$pathId").also {
                                pathRecoveryThreads[pathId] = it
                            }
                        }
                    }
                    if (recoveryThread != null) {
                        runCatching { recoveryThread.start() }.onFailure { error ->
                            synchronized(recoveryLock) {
                                if (pathRecoveryThreads[pathId] === recoveryThread) {
                                    pathRecoveryThreads.remove(pathId)
                                }
                            }
                            if (running.get() && recoveryToken.get()) {
                                Log.w(TAG, "Unable to start TURN path $pathId recovery worker", error)
                            }
                        }
                    }
                }
                try {
                    Thread.sleep(1_000)
                } catch (_: InterruptedException) {
                    return
                }
            }
        } finally {
            synchronized(recoveryLock) { recoveryTokens.remove(recoveryToken) }
        }
    }

    private fun recoverPath(
        pathId: Int,
        profile: ConnectionProfile,
        transport: NativeTransport,
        handle: Long,
        credentialBroker: VkCallsCredentialProvider.CredentialBroker,
        failures: ConcurrentHashMap<Int, Int>,
        nextAttemptAt: ConcurrentHashMap<Int, Long>,
        rejectedCredentials: LinkedHashSet<String>,
        recoveryToken: AtomicBoolean,
    ) {
        var credentialFingerprint: String? = null
        try {
            if (!running.get() || !recoveryToken.get()) return
            val credentialsJson = credentialBroker.obtainCredentials()
            credentialFingerprint = TurnQuotaRetryPolicy.fingerprint(credentialsJson)
            val alreadyRejected = synchronized(recoveryLock) {
                TurnQuotaRetryPolicy.wasRejected(rejectedCredentials, credentialFingerprint)
            }
            if (alreadyRejected) throw IllegalStateException("VK Calls returned credentials already rejected by TURN")
            if (!running.get() || !recoveryToken.get()) return
            check(transport.nativeTurnRecoverPath(
                this, handle, profile.host, profile.port, credentialsJson,
                decodeHexKey(profile.pinnedServerPublicKeyHex), profile.credential, pathId,
            )) { "Native TURN path replacement was rejected" }
            failures.remove(pathId)
            nextAttemptAt.remove(pathId)
            if (running.get() && recoveryToken.get()) updateNotification("VPN активен · TURN-путь $pathId восстановлен")
        } catch (error: Throwable) {
            if (!running.get() || !recoveryToken.get()) return
            if (error.message == "TURN_ALLOCATION_QUOTA_486" && credentialFingerprint != null) {
                synchronized(recoveryLock) {
                    TurnQuotaRetryPolicy.rememberRejectedFingerprint(rejectedCredentials, credentialFingerprint)
                }
            }
            val count = failures.compute(pathId) { _, previous -> (previous ?: 0) + 1 }!! - 1
            val jitterMillis = java.util.concurrent.ThreadLocalRandom.current().nextLong(0L, 501L)
            val delayMillis = TurnRecoveryBackoffPolicy.delayMillis(count, jitterMillis)
            nextAttemptAt[pathId] = SystemClock.elapsedRealtime() + delayMillis
            if (running.get() && recoveryToken.get()) {
                Log.w(TAG, "TURN path $pathId recovery failed; retry in ${delayMillis}ms", error)
                updateNotification("VPN активен · восстановление TURN-пути $pathId")
            }
        } finally {
            synchronized(recoveryLock) {
                if (pathRecoveryThreads[pathId] === Thread.currentThread()) pathRecoveryThreads.remove(pathId)
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
        val recoveryThreads = synchronized(recoveryLock) {
            recoveryTokens.forEach { it.set(false) }
            pathRecoveryThreads.values.toList()
        }
        recoveryThreads.forEach { it.interrupt() }
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
        private const val DEFAULT_TURN_PATHS = 10
    }
}
