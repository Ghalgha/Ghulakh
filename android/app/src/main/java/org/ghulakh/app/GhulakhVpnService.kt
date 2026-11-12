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
    private val lifecycleGeneration = TunnelLifecycleGeneration()
    private val nativeOperationLock = Any()

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
    private val pathRecoveryThreads = mutableMapOf<Pair<AtomicBoolean, Int>, Thread>()

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
        synchronized(this) {
            if (running.compareAndSet(false, true)) {
                val generation = lifecycleGeneration.begin()
                isActive = true
                worker = Thread({ runTunnel(generation, startId) }, "ghulakh-vpn-session").apply { start() }
            }
        }
        return START_NOT_STICKY
    }

    private fun isCurrent(generation: Long): Boolean =
        running.get() && lifecycleGeneration.isCurrent(generation)

    private fun runTunnel(generation: Long, startId: Int) {
        val credentialGroups = Collections.synchronizedList(mutableListOf<VkCallsCredentialGroup>())
        try {
            val profile = CredentialStore(this).load()
                ?: throw IllegalStateException("Профиль соединения не настроен")
            val transport = NativeTransport()
            val rejectedCredentialFingerprints = mutableSetOf<String>()
            var connectAttempt = 0
            var callsSession: VkCallsCredentialGroup? = null
            var handle = 0L
            while (true) {
                if (!isCurrent(generation)) return
                val candidate = VkCallsCredentialProvider.obtainGroup(profile.vkAccessToken, DEFAULT_TURN_PATHS)
                // Credential acquisition performs blocking HTTPS requests. The VPN may be
                // stopped while they are in flight, so serialize the generation check,
                // native connect and handle publication with native shutdown.
                try {
                    val connectedHandle = synchronized(nativeOperationLock) {
                        if (!isCurrent(generation)) {
                            null
                        } else {
                            val connected = transport.nativeTurnConnect(
                                this,
                                profile.host,
                                profile.port,
                                candidate.turnCredentialsJson,
                                decodeHexKey(profile.pinnedServerPublicKeyHex),
                                profile.credential,
                                DEFAULT_TURN_PATHS,
                            )
                            check(connected != 0L) { "Native TURN connect returned an invalid handle" }
                            if (!isCurrent(generation)) {
                                runCatching { transport.nativeTurnClose(connected) }
                                    .onFailure { closeError -> Log.w(TAG, "Failed to close stale native TURN session", closeError) }
                                null
                            } else {
                                nativeTransport = transport
                                sessionHandle = connected
                                connected
                            }
                        }
                    }
                    if (connectedHandle == null) {
                        runCatching { candidate.finish() }
                            .onFailure { finishError -> Log.w(TAG, "Failed to finish stale VK Calls credential group", finishError) }
                        return
                    }
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
                    if (!isCurrent(generation)) return
                    Thread.sleep(TurnQuotaRetryPolicy.retryDelayMillis(connectAttempt - 1))
                }
            }
            val establishedGroup = checkNotNull(callsSession)
            credentialGroups.add(establishedGroup)
            val (clientAddress, mtu) = synchronized(nativeOperationLock) {
                if (!isCurrent(generation)) return
                transport.nativeTurnClientIpv4(handle) to transport.nativeTurnMtu(handle)
            }
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
            val descriptorRetained = synchronized(this) {
                if (isCurrent(generation)) {
                    tunnelDescriptor = descriptor
                    true
                } else {
                    false
                }
            }
            if (!descriptorRetained) {
                descriptor.close()
                return
            }
            updateNotification("VPN активен · IPv4 через TURN-реле VK Calls · IPv6 блокируется")

            val input = FileInputStream(descriptor.fileDescriptor)
            val output = FileOutputStream(descriptor.fileDescriptor)

            val tunReader = Thread({
                try {
                    val buffer = ByteArray(MAX_IP_PACKET_SIZE)
                    while (isCurrent(generation)) {
                        val length = input.read(buffer)
                        if (length < 0) {
                            if (isCurrent(generation)) {
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
                    if (isCurrent(generation)) failSession(generation, "Ошибка чтения Android TUN", error)
                }
            }, "ghulakh-tun-reader")

            val tunWriter = Thread({
                try {
                    while (isCurrent(generation)) {
                        val packet = transport.nativeTurnReceivePacket(handle)
                            ?: throw IllegalStateException("TURN transport returned an empty packet result")
                        output.write(packet)
                        output.flush()
                    }
                } catch (error: Throwable) {
                    if (isCurrent(generation)) failSession(generation, "Ошибка приёма TURN-пакета", error)
                }
            }, "ghulakh-tun-writer")

            tunReader.start()
            tunWriter.start()
            val recoveryToken = AtomicBoolean(isCurrent(generation))
            synchronized(recoveryLock) {
                if (isCurrent(generation)) recoveryTokens.add(recoveryToken) else recoveryToken.set(false)
            }
            recoveryWorker = Thread({
                recoverFailedPaths(
                    profile,
                    transport,
                    handle,
                    establishedGroup.credentialBroker,
                    recoveryToken,
                    generation,
                )
            }, "ghulakh-turn-recovery").apply { start() }
            tunReader.join()
            tunWriter.join()
        } catch (error: Throwable) {
            if (isCurrent(generation)) {
                Log.e(TAG, "VPN session failed", error)
                updateNotification("Ошибка VPN · ${error.message ?: "соединение прервано"}")
            }
        } finally {
            val ownsLifecycle = isCurrent(generation)
            if (ownsLifecycle) stopTunnel()
            synchronized(credentialGroups) {
                credentialGroups.forEach { group ->
                    runCatching { group.finish() }
                        .onFailure { error -> Log.w(TAG, "Failed to finish VK Calls credential group", error) }
                }
                credentialGroups.clear()
            }
            if (worker === Thread.currentThread()) worker = null
            if (ownsLifecycle) stopSelfResult(startId)
        }
    }


    private fun recoverFailedPaths(
        profile: ConnectionProfile,
        transport: NativeTransport,
        handle: Long,
        credentialBroker: VkCallsCredentialProvider.CredentialBroker,
        recoveryToken: AtomicBoolean,
        generation: Long,
    ) {
        val failures = ConcurrentHashMap<Int, Int>()
        val nextAttemptAt = ConcurrentHashMap<Int, Long>()
        val rejectedCredentials = linkedSetOf<String>()
        try {
            while (isCurrent(generation) && recoveryToken.get()) {
                val failedPaths = runCatching { transport.nativeTurnFailedPaths(handle).toList() }
                    .getOrElse { error ->
                        if (isCurrent(generation) && recoveryToken.get()) {
                            Log.w(TAG, "Unable to inspect TURN path health", error)
                        }
                        emptyList()
                    }
                for (pathId in failedPaths) {
                    if (!isCurrent(generation) || !recoveryToken.get()) break
                    val now = SystemClock.elapsedRealtime()
                    val recoveryKey = recoveryToken to pathId
                    val recoveryThread = synchronized(recoveryLock) {
                        if (!isCurrent(generation) || !recoveryToken.get() ||
                            pathRecoveryThreads.containsKey(recoveryKey) ||
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
                                    generation,
                                )
                            }, "ghulakh-turn-recovery-$pathId").also {
                                pathRecoveryThreads[recoveryKey] = it
                            }
                        }
                    }
                    if (recoveryThread != null) {
                        runCatching { recoveryThread.start() }.onFailure { error ->
                            synchronized(recoveryLock) {
                                if (pathRecoveryThreads[recoveryKey] === recoveryThread) {
                                    pathRecoveryThreads.remove(recoveryKey)
                                }
                            }
                            if (isCurrent(generation) && recoveryToken.get()) {
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
        generation: Long,
    ) {
        var credentialFingerprint: String? = null
        try {
            if (!isCurrent(generation) || !recoveryToken.get()) return
            val credentialsJson = credentialBroker.obtainCredentials()
            credentialFingerprint = TurnQuotaRetryPolicy.fingerprint(credentialsJson)
            val alreadyRejected = synchronized(recoveryLock) {
                TurnQuotaRetryPolicy.wasRejected(rejectedCredentials, credentialFingerprint)
            }
            if (alreadyRejected) throw IllegalStateException("VK Calls returned credentials already rejected by TURN")
            if (!isCurrent(generation) || !recoveryToken.get()) return
            val recovered = synchronized(nativeOperationLock) {
                if (!isCurrent(generation) || !recoveryToken.get()) {
                    false
                } else {
                    transport.nativeTurnRecoverPath(
                        this, handle, profile.host, profile.port, credentialsJson,
                        decodeHexKey(profile.pinnedServerPublicKeyHex), profile.credential, pathId,
                    )
                }
            }
            if (!isCurrent(generation) || !recoveryToken.get()) return
            check(recovered) { "Native TURN path replacement was rejected" }
            failures.remove(pathId)
            nextAttemptAt.remove(pathId)
            if (isCurrent(generation) && recoveryToken.get()) updateNotification("VPN активен · TURN-путь $pathId восстановлен")
        } catch (error: Throwable) {
            if (!isCurrent(generation) || !recoveryToken.get()) return
            if (error.message == "TURN_ALLOCATION_QUOTA_486" && credentialFingerprint != null) {
                synchronized(recoveryLock) {
                    TurnQuotaRetryPolicy.rememberRejectedFingerprint(rejectedCredentials, credentialFingerprint)
                }
            }
            val count = failures.compute(pathId) { _, previous -> (previous ?: 0) + 1 }!! - 1
            val jitterMillis = java.util.concurrent.ThreadLocalRandom.current().nextLong(0L, 501L)
            val delayMillis = TurnRecoveryBackoffPolicy.delayMillis(count, jitterMillis)
            nextAttemptAt[pathId] = SystemClock.elapsedRealtime() + delayMillis
            if (isCurrent(generation) && recoveryToken.get()) {
                Log.w(TAG, "TURN path $pathId recovery failed; retry in ${delayMillis}ms", error)
                updateNotification("VPN активен · восстановление TURN-пути $pathId")
            }
        } finally {
            synchronized(recoveryLock) {
                val recoveryKey = recoveryToken to pathId
                if (pathRecoveryThreads[recoveryKey] === Thread.currentThread()) {
                    pathRecoveryThreads.remove(recoveryKey)
                }
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

    private fun failSession(generation: Long, message: String, error: Throwable) {
        if (!isCurrent(generation)) return
        Log.e(TAG, message, error)
        updateNotification("$message: ${error.message ?: "ошибка"}")
        stopTunnel()
        stopSelf()
    }

    @Synchronized
    private fun stopTunnel() {
        running.set(false)
        lifecycleGeneration.invalidate()
        val activeWorker = worker
        worker = null
        if (activeWorker != null && activeWorker !== Thread.currentThread()) {
            activeWorker.interrupt()
        }
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

        synchronized(nativeOperationLock) {
            val handle = sessionHandle
            sessionHandle = 0L
            val transport = nativeTransport
            nativeTransport = null
            if (handle != 0L) {
                try {
                    transport?.nativeTurnClose(handle)
                } catch (error: Throwable) {
                    Log.w(TAG, "Failed to close native TURN session", error)
                }
            }
        }
    }

    override fun onRevoke() {
        stopTunnel()
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        isActive = false
        stopTunnel()
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
