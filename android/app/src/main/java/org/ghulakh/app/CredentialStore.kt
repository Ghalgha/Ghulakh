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
    val vkAccessToken: String = "",
    val pinnedServerPublicKeyHex: String = "",
)

/** Stores the VK access token, tunnel credential and pinned Noise key encrypted with Android Keystore. */
class CredentialStore(context: Context) {
    private val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    fun save(profile: ConnectionProfile) {
        require(profile.host.isNotBlank())
        require(profile.port in 1..65535)
        require(profile.credential.isNotBlank())
        require(profile.vkAccessToken.isNotBlank())
        require(profile.pinnedServerPublicKeyHex.matches(Regex("[0-9a-fA-F]{64}")))

        val credential = encrypt(profile.credential.toByteArray(StandardCharsets.UTF_8))
        val vkToken = encrypt(profile.vkAccessToken.toByteArray(StandardCharsets.UTF_8))
        val pinnedKey = encrypt(profile.pinnedServerPublicKeyHex.lowercase().toByteArray(StandardCharsets.UTF_8))

        preferences.edit()
            .putString("host", profile.host)
            .putInt("port", profile.port)
            .putString("credential_iv", credential.first)
            .putString("credential_data", credential.second)
            .putString("vk_access_token_iv", vkToken.first)
            .putString("vk_access_token_data", vkToken.second)
            .putString("pinned_key_iv", pinnedKey.first)
            .putString("pinned_key_data", pinnedKey.second)
            .apply()
    }

    fun load(): ConnectionProfile? {
        val host = preferences.getString("host", null) ?: return null
        val port = preferences.getInt("port", 0)
        val credentialIv = preferences.getString("credential_iv", null) ?: return null
        val credentialData = preferences.getString("credential_data", null) ?: return null
        val vkTokenIv = preferences.getString("vk_access_token_iv", null) ?: return null
        val vkTokenData = preferences.getString("vk_access_token_data", null) ?: return null
        val pinnedKeyIv = preferences.getString("pinned_key_iv", null) ?: return null
        val pinnedKeyData = preferences.getString("pinned_key_data", null) ?: return null

        val credential = decrypt(credentialIv, credentialData)
            .let { String(it, StandardCharsets.UTF_8) }
        val vkAccessToken = decrypt(vkTokenIv, vkTokenData)
            .let { String(it, StandardCharsets.UTF_8) }
        val pinnedKey = decrypt(pinnedKeyIv, pinnedKeyData)
            .let { String(it, StandardCharsets.UTF_8) }
        return ConnectionProfile(
            host = host,
            port = port,
            serverName = "",
            credential = credential,
            rootCertificateDer = byteArrayOf(),
            vkAccessToken = vkAccessToken,
            pinnedServerPublicKeyHex = pinnedKey,
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
