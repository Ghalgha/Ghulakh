package org.ghulakh.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Bridges Android's packet TUN to the native QUIC transport.
 * The native layer protects the underlying UDP socket before VPN routes are installed.
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

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (VpnService.prepare(this) != null) {
            stopSelf()
            return START_NOT_STICKY
        }
        try {
            startForeground(NOTIFICATION_ID, notification("Подключение к серверу"))
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
        try {
            val profile = CredentialStore(this).load()
                ?: throw IllegalStateException("Профиль соединения не настроен")
            val transport = NativeTransport()
            nativeTransport = transport

            val handle = transport.nativeConnect(
                this,
                profile.host,
                profile.port,
                profile.serverName,
                profile.rootCertificateDer,
                profile.credential,
            )
            sessionHandle = handle

            if (!transport.nativeTunnelEnabled(handle)) {
                throw IllegalStateException("На сервере выключен IPv4 TUN; маршрутизация запрещена")
            }
            if (!transport.nativeForwardingEnabled(handle)) {
                throw IllegalStateException("Серверный IP forwarding/NAT/firewall не подтверждён администратором")
            }

            val clientAddress = transport.nativeClientIpv4(handle)
            val descriptor = Builder()
                .setSession("Ghulakh")
                .setMtu(TUN_MTU)
                .addAddress(clientAddress, 32)
                .addAddress("fd77::2", 128)
                .addRoute("0.0.0.0", 0)
                // IPv6 is captured to prevent leaks; the current server drops IPv6 packets.
                .addRoute("::", 0)
                .addDnsServer("1.1.1.1")
                .establish()
                ?: throw IllegalStateException("Android не создал TUN-интерфейс")
            tunnelDescriptor = descriptor
            updateNotification("VPN активен · IPv4 через QUIC · IPv6 отключён")

            val input = FileInputStream(descriptor.fileDescriptor)
            val output = FileOutputStream(descriptor.fileDescriptor)

            val tunReader = Thread({
                try {
                    val buffer = ByteArray(MAX_IP_PACKET_SIZE)
                    while (running.get()) {
                        val length = input.read(buffer)
                        if (length < 0) break
                        if (length > 0 && !transport.nativeSendPacket(handle, buffer.copyOf(length))) {
                            throw IllegalStateException("QUIC-транспорт отклонил IP-пакет")
                        }
                    }
                } catch (error: Throwable) {
                    if (running.get()) failSession("Ошибка чтения Android TUN", error)
                }
            }, "ghulakh-tun-reader")

            val tunWriter = Thread({
                try {
                    while (running.get()) {
                        val packet = transport.nativeReceivePacket(handle) ?: continue
                        output.write(packet)
                        output.flush()
                    }
                } catch (error: Throwable) {
                    if (running.get()) failSession("Ошибка приёма QUIC-пакета", error)
                }
            }, "ghulakh-tun-writer")

            tunReader.start()
            tunWriter.start()
            tunReader.join()
            tunWriter.join()
        } catch (error: Throwable) {
            if (running.get()) {
                Log.e(TAG, "VPN session failed", error)
                updateNotification("Ошибка VPN · ${error.message ?: "соединение прервано"}")
            }
        } finally {
            stopTunnel()
            stopSelf()
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
        try {
            tunnelDescriptor?.close()
        } catch (_: Exception) {
        }
        tunnelDescriptor = null

        val handle = sessionHandle
        sessionHandle = 0L
        if (handle != 0L) {
            try {
                nativeTransport?.nativeClose(handle)
            } catch (error: Throwable) {
                Log.w(TAG, "Failed to close native QUIC session", error)
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
        private const val TUN_MTU = 1100
        private const val MAX_IP_PACKET_SIZE = 65_535
    }
}
