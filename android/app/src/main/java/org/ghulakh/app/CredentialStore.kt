package org.ghulakh.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal inline fun <T> ByteArray.useWiped(block: (ByteArray) -> T): T {
    try {
        return block(this)
    } finally {
        fill(0)
    }
}

data class ConnectionProfile(
    val host: String,
    val port: Int,
    val serverName: String,
    val credential: String,
    val rootCertificateDer: ByteArray,
    val vkAccessToken: String = "",
    val pinnedServerPublicKeyHex: String = "",
) {
    override fun toString(): String =
        "ConnectionProfile(host=$host, port=$port, serverName=$serverName, credential=<redacted>, rootCertificateDer=<redacted>, vkAccessToken=<redacted>, pinnedServerPublicKeyHex=<redacted>)"

    override fun equals(other: Any?): Boolean =
        other is ConnectionProfile &&
            host == other.host &&
            port == other.port &&
            serverName == other.serverName &&
            credential == other.credential &&
            rootCertificateDer.contentEquals(other.rootCertificateDer) &&
            vkAccessToken == other.vkAccessToken &&
            pinnedServerPublicKeyHex == other.pinnedServerPublicKeyHex

    override fun hashCode(): Int {
        var result = host.hashCode()
        result = 31 * result + port
        result = 31 * result + serverName.hashCode()
        result = 31 * result + credential.hashCode()
        result = 31 * result + rootCertificateDer.contentHashCode()
        result = 31 * result + vkAccessToken.hashCode()
        result = 31 * result + pinnedServerPublicKeyHex.hashCode()
        return result
    }
}

open class CredentialStoreException(message: String, cause: Throwable? = null) : Exception(message, cause) {
    class KeyUnavailable(cause: Throwable? = null) :
        CredentialStoreException("Ключ Android Keystore отсутствует. Сохранённый профиль нельзя расшифровать; введите параметры заново.", cause)

    class Corrupted(cause: Throwable? = null) :
        CredentialStoreException("Сохранённый профиль повреждён или не прошёл проверку подлинности.", cause)

    class PersistenceFailure :
        CredentialStoreException("Android не подтвердил сохранение профиля.")
}

internal interface ProfileKeyProvider {
    fun getForEncryption(): SecretKey
    fun getForDecryption(): SecretKey?
    fun delete()
}

private class AndroidProfileKeyProvider : ProfileKeyProvider {
    override fun getForEncryption(): SecretKey {
        loadKeyStore().getKey(KEY_ALIAS, null)?.let { return it as SecretKey }
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

    override fun getForDecryption(): SecretKey? =
        loadKeyStore().getKey(KEY_ALIAS, null) as? SecretKey

    override fun delete() {
        val keyStore = loadKeyStore()
        if (keyStore.containsAlias(KEY_ALIAS)) keyStore.deleteEntry(KEY_ALIAS)
    }

    private fun loadKeyStore(): KeyStore =
        KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }

    private companion object {
        const val ANDROID_KEY_STORE = "AndroidKeyStore"
        const val KEY_ALIAS = "org.ghulakh.app.connection-key.v1"
    }
}

private class WipingByteArrayOutputStream : ByteArrayOutputStream() {
    fun wipe() {
        buf.fill(0)
        reset()
    }
}

/**
 * Stores the complete connection profile as one authenticated AES-GCM payload.
 * Decryption never creates a replacement key: a lost Keystore key is reported
 * explicitly instead of silently replacing it and making recovery impossible.
 */
class CredentialStore internal constructor(
    context: Context,
    private val keyProvider: ProfileKeyProvider,
) {
    constructor(context: Context) : this(context.applicationContext, AndroidProfileKeyProvider())

    private val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    @Throws(CredentialStoreException::class)
    fun save(profile: ConnectionProfile) {
        validate(profile)
        serialize(profile).useWiped { plaintext ->
            val encrypted = encrypt(plaintext)
            encrypted.first.useWiped { iv ->
                encrypted.second.useWiped { ciphertext ->
                    val committed = preferences.edit()
                        .clear()
                        .putInt(VERSION_KEY, PROFILE_VERSION)
                        .putString(IV_KEY, encode(iv))
                        .putString(DATA_KEY, encode(ciphertext))
                        .commit()
                    if (!committed) throw CredentialStoreException.PersistenceFailure()
                }
            }
        }
    }

    @Throws(CredentialStoreException::class)
    fun load(): ConnectionProfile? {
        if (preferences.contains(VERSION_KEY) || preferences.contains(DATA_KEY) || preferences.contains(IV_KEY)) {
            return loadCurrentFormat()
        }
        if (!preferences.contains("host")) return null
        return migrateLegacyProfile()
    }

    @Throws(CredentialStoreException::class)
    fun clear() {
        if (!preferences.edit().clear().commit()) {
            throw CredentialStoreException.PersistenceFailure()
        }
        try {
            keyProvider.delete()
        } catch (error: Exception) {
            throw CredentialStoreException("Не удалось удалить ключ Android Keystore.", error)
        }
    }

    private fun loadCurrentFormat(): ConnectionProfile {
        val version = preferences.getInt(VERSION_KEY, -1)
        if (version != PROFILE_VERSION) throw CredentialStoreException.Corrupted()
        val iv = preferences.getString(IV_KEY, null) ?: throw CredentialStoreException.Corrupted()
        val ciphertext = preferences.getString(DATA_KEY, null) ?: throw CredentialStoreException.Corrupted()
        return decode(iv).useWiped { decodedIv ->
            decode(ciphertext).useWiped { decodedCiphertext ->
                decrypt(decodedIv, decodedCiphertext).useWiped(::deserialize)
            }
        }
    }

    /**
     * One-time migration from the previous split-field format. The old format
     * never stored serverName or rootCertificateDer, so those are empty only
     * for profiles created by that older version.
     */
    private fun migrateLegacyProfile(): ConnectionProfile {
        val host = preferences.getString("host", null) ?: throw CredentialStoreException.Corrupted()
        val port = preferences.getInt("port", 0)
        val key = try {
            keyProvider.getForDecryption() ?: throw CredentialStoreException.KeyUnavailable()
        } catch (error: CredentialStoreException) {
            throw error
        } catch (error: Exception) {
            throw CredentialStoreException.KeyUnavailable(error)
        }

        fun legacySecret(ivKey: String, dataKey: String): String {
            val iv = preferences.getString(ivKey, null) ?: throw CredentialStoreException.Corrupted()
            val data = preferences.getString(dataKey, null) ?: throw CredentialStoreException.Corrupted()
            return try {
                decode(iv).useWiped { decodedIv ->
                    decode(data).useWiped { decodedCiphertext ->
                        val cipher = Cipher.getInstance(TRANSFORMATION)
                        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, decodedIv))
                        cipher.doFinal(decodedCiphertext).useWiped { plaintext ->
                            String(plaintext, StandardCharsets.UTF_8)
                        }
                    }
                }
            } catch (error: CredentialStoreException) {
                throw error
            } catch (error: Exception) {
                throw CredentialStoreException.Corrupted(error)
            }
        }

        val certificate = preferences.getString("root_certificate_der", null)
            ?.let(::decode) ?: byteArrayOf()
        val profile = try {
            ConnectionProfile(
                host = host,
                port = port,
                serverName = preferences.getString("server_name", "") ?: "",
                credential = legacySecret("credential_iv", "credential_data"),
                rootCertificateDer = certificate,
                vkAccessToken = legacySecret("vk_access_token_iv", "vk_access_token_data"),
                pinnedServerPublicKeyHex = legacySecret("pinned_key_iv", "pinned_key_data"),
            ).also(::validate)
        } catch (error: Exception) {
            certificate.fill(0)
            if (error is CredentialStoreException) throw error
            throw CredentialStoreException.Corrupted(error)
        }
        try {
            save(profile)
            return profile
        } catch (error: Exception) {
            certificate.fill(0)
            throw error
        }
    }

    private fun encrypt(plaintext: ByteArray): Pair<ByteArray, ByteArray> {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, keyProvider.getForEncryption())
        cipher.updateAAD(AAD)
        return cipher.iv to cipher.doFinal(plaintext)
    }

    private fun decrypt(iv: ByteArray, ciphertext: ByteArray): ByteArray {
        val key = try {
            keyProvider.getForDecryption() ?: throw CredentialStoreException.KeyUnavailable()
        } catch (error: CredentialStoreException) {
            throw error
        } catch (error: Exception) {
            throw CredentialStoreException.KeyUnavailable(error)
        }
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
            cipher.updateAAD(AAD)
            cipher.doFinal(ciphertext)
        } catch (error: AEADBadTagException) {
            throw CredentialStoreException.Corrupted(error)
        } catch (error: Exception) {
            throw CredentialStoreException.Corrupted(error)
        }
    }

    private fun serialize(profile: ConnectionProfile): ByteArray {
        val output = WipingByteArrayOutputStream()
        try {
            DataOutputStream(output).use { data ->
                data.writeInt(PROFILE_VERSION)
                data.writeString(profile.host)
                data.writeInt(profile.port)
                data.writeString(profile.serverName)
                data.writeString(profile.credential)
                data.writeBytes(profile.rootCertificateDer)
                data.writeString(profile.vkAccessToken)
                data.writeString(profile.pinnedServerPublicKeyHex)
            }
            return output.toByteArray()
        } finally {
            output.wipe()
        }
    }

    private fun deserialize(bytes: ByteArray): ConnectionProfile {
        try {
            DataInputStream(ByteArrayInputStream(bytes)).use { data ->
                if (data.readInt() != PROFILE_VERSION) throw CredentialStoreException.Corrupted()
                val profile = ConnectionProfile(
                    host = data.readString(),
                    port = data.readInt(),
                    serverName = data.readString(),
                    credential = data.readString(),
                    rootCertificateDer = data.readBytes(),
                    vkAccessToken = data.readString(),
                    pinnedServerPublicKeyHex = data.readString(),
                )
                if (data.available() != 0) throw CredentialStoreException.Corrupted()
                validate(profile)
                return profile
            }
        } catch (error: CredentialStoreException) {
            throw error
        } catch (error: Exception) {
            throw CredentialStoreException.Corrupted(error)
        }
    }

    private fun validate(profile: ConnectionProfile) {
        require(profile.host.isNotBlank()) { "Не задан адрес сервера" }
        require(profile.port in 1..65535) { "Недопустимый порт сервера" }
        require(profile.credential.isNotBlank()) { "Не задан ключ устройства" }
        require(profile.vkAccessToken.isNotBlank()) { "Не задан VK access token" }
        require(profile.pinnedServerPublicKeyHex.matches(Regex("[0-9a-fA-F]{64}"))) {
            "Noise public key должен содержать 64 hex-символа"
        }
        require(profile.rootCertificateDer.size <= MAX_CERTIFICATE_BYTES) {
            "Корневой сертификат слишком велик"
        }
    }

    private fun encode(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.NO_WRAP)
    private fun decode(value: String): ByteArray = Base64.decode(value, Base64.NO_WRAP)

    private fun DataOutputStream.writeString(value: String) {
        value.toByteArray(StandardCharsets.UTF_8).useWiped(::writeBytes)
    }

    private fun DataOutputStream.writeBytes(value: ByteArray) {
        require(value.size <= MAX_FIELD_BYTES)
        writeInt(value.size)
        write(value)
    }

    private fun DataInputStream.readString(): String =
        readBytes().useWiped { String(it, StandardCharsets.UTF_8) }

    private fun DataInputStream.readBytes(): ByteArray {
        val size = readInt()
        if (size < 0 || size > MAX_FIELD_BYTES || size > available()) {
            throw CredentialStoreException.Corrupted()
        }
        return ByteArray(size).also(::readFully)
    }

    private companion object {
        const val PREFERENCES = "ghulakh_connection_profile"
        const val PROFILE_VERSION = 2
        const val VERSION_KEY = "profile_version"
        const val IV_KEY = "profile_iv"
        const val DATA_KEY = "profile_data"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val MAX_FIELD_BYTES = 1_048_576
        const val MAX_CERTIFICATE_BYTES = 262_144
        val AAD = "org.ghulakh.app.connection-profile.v2".toByteArray(StandardCharsets.UTF_8)
    }
}
