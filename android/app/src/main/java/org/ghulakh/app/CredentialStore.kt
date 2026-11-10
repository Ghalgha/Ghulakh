package org.ghulakh.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

data class ConnectionProfile(
    val host: String,
    val port: Int,
    val serverName: String,
    val credential: String,
    val rootCertificateDer: ByteArray,
)

/** Stores device credentials and the trust anchor encrypted with an Android Keystore key. */
class CredentialStore(context: Context) {
    private val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    fun save(profile: ConnectionProfile) {
        require(profile.host.isNotBlank())
        require(profile.port in 1..65535)
        require(profile.serverName.isNotBlank())
        require(profile.credential.isNotBlank())
        require(profile.turnCredentialsJson.isNotBlank())\n        require(profile.pinnedServerPublicKeyHex.matches(Regex(\"[0-9a-fA-F]{64}\")))

        val credential = encrypt(profile.credential.toByteArray(StandardCharsets.UTF_8))
        val certificate = if (profile.rootCertificateDer.isNotEmpty()) encrypt(profile.rootCertificateDer) else null\n        val turnCredentials = encrypt(profile.turnCredentialsJson.toByteArray(StandardCharsets.UTF_8))\n        val pinnedKey = encrypt(profile.pinnedServerPublicKeyHex.lowercase().toByteArray(StandardCharsets.UTF_8))

        preferences.edit()
            .putString("host", profile.host)
            .putInt("port", profile.port)
            .putString("server_name", profile.serverName)
            .putString("credential_iv", credential.first)
            .putString("credential_data", credential.second)
            .putString("certificate_iv", certificate.first)
            .putString("certificate_data", certificate.second)
            .apply()
    }

    fun load(): ConnectionProfile? {
        val host = preferences.getString("host", null) ?: return null
        val port = preferences.getInt("port", 0)
        val serverName = preferences.getString("server_name", null) ?: return null
        val credentialIv = preferences.getString("credential_iv", null) ?: return null
        val credentialData = preferences.getString("credential_data", null) ?: return null
        val certificateIv = preferences.getString("certificate_iv", null)
        val certificateData = preferences.getString("certificate_data", null)
        val turnCredentialsIv = preferences.getString("turn_credentials_iv", null) ?: return null
        val turnCredentialsData = preferences.getString("turn_credentials_data", null) ?: return null
        val pinnedKeyIv = preferences.getString("pinned_key_iv", null) ?: return null
        val pinnedKeyData = preferences.getString("pinned_key_data", null) ?: return null

        val credential = decrypt(credentialIv, credentialData)
            .let { String(it, StandardCharsets.UTF_8) }
        val certificate = if (certificateIv != null && certificateData != null) {
            decrypt(certificateIv, certificateData)
        } else {
            byteArrayOf()
        }
        val turnCredentials = decrypt(turnCredentialsIv, turnCredentialsData)
            .let { String(it, StandardCharsets.UTF_8) }
        val pinnedKey = decrypt(pinnedKeyIv, pinnedKeyData)
            .let { String(it, StandardCharsets.UTF_8) }
        return ConnectionProfile(
            host, port, serverName, credential, certificate,
            turnCredentials, pinnedKey,
        )
    }

    fun clear() {
        preferences.edit().clear().apply()
        val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
        if (keyStore.containsAlias(KEY_ALIAS)) {
            keyStore.deleteEntry(KEY_ALIAS)
        }
    }

    private fun encrypt(plaintext: ByteArray): Pair<String, String> {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val ciphertext = cipher.doFinal(plaintext)
        return encode(cipher.iv) to encode(ciphertext)
    }

    private fun decrypt(iv: String, ciphertext: String): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(
            Cipher.DECRYPT_MODE,
            getOrCreateKey(),
            GCMParameterSpec(128, decode(iv)),
        )
        return cipher.doFinal(decode(ciphertext))
    }

    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        return generator.generateKey()
    }

    private fun encode(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.NO_WRAP)

    private fun decode(value: String): ByteArray =
        Base64.decode(value, Base64.NO_WRAP)

    private companion object {
        const val PREFERENCES = "ghulakh_connection_profile"
        const val ANDROID_KEY_STORE = "AndroidKeyStore"
        const val KEY_ALIAS = "org.ghulakh.app.connection-key.v1"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
    }
}
