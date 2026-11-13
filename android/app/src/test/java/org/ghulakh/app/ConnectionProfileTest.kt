package org.ghulakh.app

import android.content.Context
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

@RunWith(RobolectricTestRunner::class)
class ConnectionProfileTest {
    @Test
    fun completeProfileRoundTripsWithoutLosingAnyField() {
        val context = RuntimeEnvironment.getApplication()
        val store = CredentialStore(context, TestProfileKeyProvider())
        val profile = sampleProfile()
        store.save(profile)
        assertEquals(profile, store.load())
    }

    @Test
    fun profileFieldsAreStoredAsOneEncryptedPayload() {
        val context = RuntimeEnvironment.getApplication()
        val store = CredentialStore(context, TestProfileKeyProvider())
        val profile = sampleProfile()
        store.save(profile)
        val persisted = context.getSharedPreferences("ghulakh_connection_profile", Context.MODE_PRIVATE)
            .all.values.joinToString("|")
        listOf(profile.host, profile.serverName, profile.credential, profile.vkAccessToken, profile.pinnedServerPublicKeyHex)
            .forEach { assertFalse(persisted.contains(it)) }
        assertFalse(persisted.contains("certificate-der"))
    }

    @Test
    fun missingKeystoreKeyIsReportedAndNeverRecreatedDuringLoad() {
        val context = RuntimeEnvironment.getApplication()
        val keys = TestProfileKeyProvider()
        val store = CredentialStore(context, keys)
        store.save(sampleProfile())
        keys.available = false
        assertThrows(CredentialStoreException.KeyUnavailable::class.java) { store.load() }
        assertEquals(1, keys.encryptionKeyCreations)
    }

    @Test
    fun authenticatedPayloadRejectsTampering() {
        val context = RuntimeEnvironment.getApplication()
        val store = CredentialStore(context, TestProfileKeyProvider())
        store.save(sampleProfile())
        val prefs = context.getSharedPreferences("ghulakh_connection_profile", Context.MODE_PRIVATE)
        val original = prefs.getString("profile_data", null)!!
        prefs.edit().putString("profile_data", original.dropLast(4) + "AAAA").commit()
        assertThrows(CredentialStoreException.Corrupted::class.java) { store.load() }
    }

    @Test
    fun clearRemovesProfileAndItsEncryptionKey() {
        val context = RuntimeEnvironment.getApplication()
        val keys = TestProfileKeyProvider()
        val store = CredentialStore(context, keys)
        store.save(sampleProfile())
        store.clear()
        assertNull(store.load())
        assertFalse(keys.keyPresent)
    }

    @Test
    fun diagnosticStringDoesNotExposeSecretsOrCertificateBytes() {
        val diagnostic = sampleProfile().toString()
        assertFalse(diagnostic.contains("device-credential-secret"))
        assertFalse(diagnostic.contains("vk-access-token-secret"))
        assertFalse(diagnostic.contains("a".repeat(64)))
        assertFalse(diagnostic.contains("certificate-der"))
    }

    private fun sampleProfile() = ConnectionProfile(
        host = "vpn.example.invalid",
        port = 443,
        serverName = "tls.example.invalid",
        credential = "device-credential-secret",
        rootCertificateDer = "certificate-der".toByteArray(),
        vkAccessToken = "vk-access-token-secret",
        pinnedServerPublicKeyHex = "a".repeat(64),
    )

    private class TestProfileKeyProvider : ProfileKeyProvider {
        var available = true
        var keyPresent = false
        var encryptionKeyCreations = 0
        private val key: SecretKey = SecretKeySpec(ByteArray(32) { (it + 1).toByte() }, "AES")

        override fun getForEncryption(): SecretKey {
            if (!keyPresent) {
                keyPresent = true
                encryptionKeyCreations++
            }
            return key
        }
        override fun getForDecryption(): SecretKey? = if (available && keyPresent) key else null
        override fun delete() { keyPresent = false }
    }
}
