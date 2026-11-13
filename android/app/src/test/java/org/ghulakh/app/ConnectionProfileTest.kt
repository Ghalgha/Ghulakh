package org.ghulakh.app

import org.junit.Assert.assertFalse
import org.junit.Test

class ConnectionProfileTest {
    @Test
    fun diagnosticStringRedactsCredentialsAndAccessToken() {
        val profile = ConnectionProfile(
            host = "vpn.example.invalid",
            port = 443,
            serverName = "vpn.example.invalid",
            credential = "device-credential-secret",
            rootCertificateDer = byteArrayOf(1, 2, 3),
            vkAccessToken = "vk-access-token-secret",
            pinnedServerPublicKeyHex = "a".repeat(64),
        )

        val diagnostic = profile.toString()
        assertFalse(diagnostic.contains("device-credential-secret"))
        assertFalse(diagnostic.contains("vk-access-token-secret"))
        assertFalse(diagnostic.contains("a".repeat(64)))
    }
}
