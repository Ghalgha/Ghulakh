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

class MainActivity : Activity() {
    private lateinit var store: CredentialStore
    private lateinit var hostInput: EditText
    private lateinit var portInput: EditText
    private lateinit var credentialInput: EditText
    private lateinit var vkAccessTokenInput: EditText
    private lateinit var pinnedServerKeyInput: EditText
    private lateinit var status: TextView

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

        hostInput = addField(content, "Адрес TURN gateway", "vpn.example.org")
        portInput = addField(content, "UDP-порт TURN gateway", "4434", numeric = true)
        credentialInput = addField(content, "Индивидуальный ключ устройства", "Вставьте credential")
        credentialInput.inputType = android.text.InputType.TYPE_CLASS_TEXT or
            android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
        credentialInput.isSaveEnabled = false

        vkAccessTokenInput = addField(
            content,
            "VK access token",
            "Вставьте пользовательский токен VK",
        ).apply {
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
            isSaveEnabled = false
        }
        pinnedServerKeyInput = addField(
            content,
            "Закреплённый Noise public key сервера (64 hex)",
            "64 шестнадцатеричных символа",
        )

        content.addView(Button(this).apply {
            text = "Сохранить настройки"
            setOnClickListener { saveProfile() }
        })
        content.addView(Button(this).apply {
            text = "Проверить профиль TURN"
            setOnClickListener { testConnection() }
        })
        content.addView(Button(this).apply {
            text = "Очистить сохранённые данные"
            setOnClickListener { clearProfile() }
        })

        status = TextView(this).apply {
            text = "Используется защищённый VPN-туннель через TURN-реле VK Calls."
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
            credentialInput.setText(profile.credential)
            vkAccessTokenInput.setText(profile.vkAccessToken)
            pinnedServerKeyInput.setText(profile.pinnedServerPublicKeyHex)
            status.text = "Настройки загружены. VPN-туннель не запущен."
        } catch (error: Exception) {
            status.text = "Не удалось расшифровать настройки: ${error.message}"
        }
    }

    private fun saveProfile() {
        try {
            val port = portInput.text.toString().toInt()
            val key = pinnedServerKeyInput.text.toString().trim()
            store.save(ConnectionProfile(
                host = hostInput.text.toString().trim(),
                port = port,
                serverName = "",
                credential = credentialInput.text.toString(),
                rootCertificateDer = byteArrayOf(),
                vkAccessToken = vkAccessTokenInput.text.toString(),
                pinnedServerPublicKeyHex = key,
            ))
            status.text = "Профиль TURN и секреты зашифрованы ключом Android Keystore."
        } catch (error: Exception) {
            status.text = "Не удалось сохранить настройки: ${error.message}"
        }
    }

    private fun testConnection() {
        if (GhulakhVpnService.isActive) {
            status.text = "Остановите VPN перед проверкой профиля."
            return
        }
        try {
            val profile = store.load() ?: throw IllegalStateException("Сначала сохраните настройки")
            require(profile.vkAccessToken.isNotBlank()) { "Не задан VK access token" }
            require(profile.pinnedServerPublicKeyHex.matches(Regex("[0-9a-fA-F]{64}"))) {
                "Закреплённый Noise public key должен содержать 64 hex-символа"
            }
            status.text = "Профиль проверен локально. VK Calls и TURN credentials будут запрошены при запуске VPN."
        } catch (error: Exception) {
            status.text = "Профиль TURN некорректен: ${error.message}"
        }
    }

    private fun clearProfile() {
        if (GhulakhVpnService.isActive) {
            status.text = "Остановите VPN перед удалением профиля."
            return
        }
        try {
            store.clear()
            credentialInput.text.clear()
            vkAccessTokenInput.text.clear()
            pinnedServerKeyInput.text.clear()
            hostInput.text.clear()
            portInput.text.clear()
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
        const val REQUEST_VPN_PERMISSION = 1001
    }
}
