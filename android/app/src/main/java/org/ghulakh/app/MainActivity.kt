package org.ghulakh.app

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

class MainActivity : Activity() {
    private lateinit var store: CredentialStore
    private lateinit var hostInput: EditText
    private lateinit var portInput: EditText
    private lateinit var serverNameInput: EditText
    private lateinit var credentialInput: EditText
    private lateinit var certificateStatus: TextView
    private lateinit var status: TextView
    private var certificateDer: ByteArray? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = CredentialStore(this)

        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 40, 32, 32)
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            )
        }

        content.addView(TextView(this).apply {
            text = "ГӀулакх"
            textSize = 28f
        })
        content.addView(TextView(this).apply {
            text = "Ghulakh · исследовательская сборка 0.1.0"
            textSize = 14f
        })

        hostInput = addField(content, "Адрес сервера", "vpn.example.org")
        portInput = addField(content, "UDP-порт", "4433", numeric = true)
        serverNameInput = addField(content, "Имя узла в TLS-сертификате", "vpn.example.org")
        credentialInput = addField(content, "Индивидуальный ключ устройства", "Вставьте credential")
        credentialInput.inputType = android.text.InputType.TYPE_CLASS_TEXT or
            android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
        credentialInput.isSaveEnabled = false

        certificateStatus = TextView(this).apply {
            text = "Доверенный сертификат не выбран"
            setPadding(0, 20, 0, 8)
        }
        content.addView(certificateStatus)

        content.addView(Button(this).apply {
            text = "Импортировать доверенный сертификат"
            setOnClickListener { chooseCertificate() }
        })
        content.addView(Button(this).apply {
            text = "Сохранить настройки"
            setOnClickListener { saveProfile() }
        })
        content.addView(Button(this).apply {
            text = "Проверить соединение"
            setOnClickListener { testConnection() }
        })
        content.addView(Button(this).apply {
            text = "Очистить сохранённые данные"
            setOnClickListener { clearProfile() }
        })

        status = TextView(this).apply {
            text = "VPN-туннель и маршрутизация пока не активируются."
            textSize = 15f
            setPadding(0, 24, 0, 16)
        }
        content.addView(status)
        content.addView(Button(this).apply {
            text = "Запустить VPN"
            setOnClickListener { startVpn() }
        })
        content.addView(Button(this).apply {
            text = "Остановить VPN"
            setOnClickListener {
                stopService(Intent(this@MainActivity, GhulakhVpnService::class.java))
                status.text = "Запрос на остановку VPN отправлен."
            }
        })

        setContentView(ScrollView(this).apply {
            addView(content)
        })
        restoreProfile()
    }

    private fun addField(
        parent: LinearLayout,
        label: String,
        hint: String,
        numeric: Boolean = false,
    ): EditText {
        parent.addView(TextView(this).apply {
            text = label
            setPadding(0, 18, 0, 4)
        })
        return EditText(this).apply {
            this.hint = hint
            if (numeric) {
                inputType = android.text.InputType.TYPE_CLASS_NUMBER
            }
            parent.addView(this, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ))
        }
    }

    private fun restoreProfile() {
        try {
            val profile = store.load() ?: return
            hostInput.setText(profile.host)
            portInput.setText(profile.port.toString())
            serverNameInput.setText(profile.serverName)
            credentialInput.setText(profile.credential)
            certificateDer = profile.rootCertificateDer
            certificateStatus.text = "Доверенный сертификат загружен из Android Keystore-хранилища"
            status.text = "Настройки загружены. VPN-туннель не запущен."
        } catch (error: Exception) {
            status.text = "Не удалось расшифровать настройки: ${error.message}"
        }
    }

    private fun chooseCertificate() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        @Suppress("DEPRECATION")
        startActivityForResult(intent, REQUEST_CERTIFICATE)
    }

    @Deprecated("Deprecated by Android; retained for the minimal file picker flow")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN_PERMISSION) {
            if (resultCode == RESULT_OK) {
                startVpnService()
            } else {
                status.text = "Разрешение VPN не выдано."
            }
            return
        }
        if (requestCode != REQUEST_CERTIFICATE || resultCode != RESULT_OK) return
        val uri = data?.data ?: return
        try {
            val certificate = contentResolver.openInputStream(uri).use { input ->
                val stream = requireNotNull(input) { "Не удалось открыть файл сертификата" }
                CertificateFactory.getInstance("X.509")
                    .generateCertificate(stream) as X509Certificate
            }
            certificateDer = certificate.encoded
            certificateStatus.text = "Сертификат выбран: ${certificate.subjectX500Principal.name}"
        } catch (error: Exception) {
            status.text = "Ошибка импорта сертификата: ${error.message}"
        }
    }

    private fun saveProfile() {
        try {
            val port = portInput.text.toString().toInt()
            val certificate = certificateDer
                ?: store.load()?.rootCertificateDer
                ?: throw IllegalArgumentException("Сначала импортируйте доверенный сертификат")
            store.save(ConnectionProfile(
                host = hostInput.text.toString().trim(),
                port = port,
                serverName = serverNameInput.text.toString().trim(),
                credential = credentialInput.text.toString(),
                rootCertificateDer = certificate,
            ))
            certificateDer = certificate
            certificateStatus.text = "Сертификат и credential зашифрованы ключом Android Keystore"
            status.text = "Настройки сохранены. Подключение ещё не выполнялось."
        } catch (error: Exception) {
            status.text = "Не удалось сохранить настройки: ${error.message}"
        }
    }

    private fun testConnection() {
        if (GhulakhVpnService.isActive) {
            status.text = "Остановите VPN перед отдельной проверкой соединения."
            return
        }
        val profile = try {
            store.load() ?: throw IllegalStateException("Сначала сохраните настройки")
        } catch (error: Exception) {
            status.text = error.message ?: "Профиль недоступен"
            return
        }

        status.text = "Проверка QUIC-соединения…"
        Thread {
            var transport: NativeTransport? = null
            var session = 0L
            try {
                val nativeTransport = NativeTransport()
                transport = nativeTransport
                session = nativeTransport.nativeConnect(
                    null,
                    profile.host,
                    profile.port,
                    profile.serverName,
                    profile.rootCertificateDer,
                    profile.credential,
                )
                check(nativeTransport.nativePing(session)) { "Сервер не подтвердил ping" }
                val tunnelReady = nativeTransport.nativeTunnelEnabled(session)
                val forwardingReady = nativeTransport.nativeForwardingEnabled(session)
                nativeTransport.nativeClose(session)
                session = 0L
                runOnUiThread {
                    status.text = when {
                        !tunnelReady -> "QUIC, TLS и аутентификация успешны, но серверный TUN выключен."
                        !forwardingReady -> "Серверный TUN включён, но администратор не подтвердил настройку IP forwarding/NAT/firewall. VPN запускать нельзя."
                        else -> "QUIC, TLS, аутентификация и готовность серверной маршрутизации подтверждены."
                    }
                }
            } catch (error: Throwable) {
                if (session != 0L) {
                    runCatching { transport?.nativeClose(session) }
                }
                runOnUiThread {
                    status.text = "Ошибка соединения: ${error.message}"
                }
            }
        }.start()
    }

    private fun clearProfile() {
        if (GhulakhVpnService.isActive) {
            status.text = "Остановите VPN перед удалением профиля."
            return
        }
        try {
            store.clear()
            credentialInput.text.clear()
            certificateDer = null
            certificateStatus.text = "Доверенный сертификат не выбран"
            status.text = "Локальный профиль и ключ Android Keystore удалены."
        } catch (error: Exception) {
            status.text = "Не удалось очистить профиль: ${error.message}"
        }
    }

    private fun startVpn() {
        if (GhulakhVpnService.isActive) {
            status.text = "VPN уже запущен."
            return
        }
        val profileAvailable = try {
            store.load() != null
        } catch (error: Exception) {
            status.text = "Не удалось открыть профиль: ${error.message}"
            return
        }
        if (!profileAvailable) {
            status.text = "Сначала сохраните профиль соединения."
            return
        }
        val permissionIntent = VpnService.prepare(this)
        if (permissionIntent == null) {
            startVpnService()
        } else {
            @Suppress("DEPRECATION")
            startActivityForResult(permissionIntent, REQUEST_VPN_PERMISSION)
        }
    }

    private fun startVpnService() {
        try {
            status.text = "Запуск VPN-сервиса…"
            startForegroundService(Intent(this, GhulakhVpnService::class.java))
        } catch (error: Exception) {
            status.text = "Не удалось запустить VPN: ${error.message}"
        }
    }

    private companion object {
        const val REQUEST_CERTIFICATE = 1002
        const val REQUEST_VPN_PERMISSION = 1001
    }
}
