package org.ghulakh.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Test

class VkCallsCredentialProviderTest {
    @Test
    fun credentialBrokerObtainsFreshDistinctCredentialsForPathRecovery() {
        val initial = credentialsJson("initial-user", "initial-secret")
        var fetchCount = 0
        var finishedSessions = 0
        val broker = VkCallsCredentialProvider.CredentialBroker(
            accessToken = "test-access-token",
            conversationId = "test-conversation",
            initialCredentialsJson = initial,
            sessionFetcher = {
                fetchCount += 1
                VkCallsSession(
                    turnCredentialsJson = credentialsJson(
                        "replacement-user-$fetchCount",
                        "replacement-secret-$fetchCount",
                    ),
                    apiUrl = "https://calls.example.invalid/",
                    sessionKey = "test-session-$fetchCount",
                    conversationId = "test-conversation",
                    finishAction = { finishedSessions += 1 },
                )
            },
        )

        val replacement = broker.obtainCredentials()

        assertNotEquals(
            TurnQuotaRetryPolicy.fingerprint(initial),
            TurnQuotaRetryPolicy.fingerprint(replacement),
        )
        assertEquals(1, fetchCount)

        val nextReplacement = broker.obtainCredentials()
        assertNotEquals(
            TurnQuotaRetryPolicy.fingerprint(replacement),
            TurnQuotaRetryPolicy.fingerprint(nextReplacement),
        )
        assertEquals(2, fetchCount)

        broker.finish()
        broker.finish()
        assertEquals("each replacement session is finished exactly once", 2, finishedSessions)
    }

    @Test
    fun credentialModelsRedactSecretsFromDiagnosticStrings() {
        val credentialJson = credentialsJson("turn-user", "turn-password-secret")
        val session = VkCallsSession(
            turnCredentialsJson = credentialJson,
            apiUrl = "https://calls.example.invalid/",
            sessionKey = "calls-session-secret",
            conversationId = "conversation-secret",
            finishAction = {},
        )
        val broker = VkCallsCredentialProvider.CredentialBroker(
            accessToken = "vk-access-token-secret",
            conversationId = "conversation-secret",
            initialCredentialsJson = credentialJson,
            sessionFetcher = { error("not used") },
        )
        val group = VkCallsCredentialGroup(
            turnCredentialsJson = credentialJson,
            ownerSession = session,
            credentialBroker = broker,
        )

        val diagnostics = listOf(session.toString(), group.toString()).joinToString("\\n")
        for (secret in listOf(
            "turn-password-secret",
            "calls-session-secret",
            "conversation-secret",
            "vk-access-token-secret",
        )) {
            assertFalse("diagnostics exposed $secret", diagnostics.contains(secret))
        }
        assertFalse(diagnostics.contains("turn-user"))
    }

    private fun credentialsJson(username: String, password: String): String =
        """{"turn_server":{"username":"$username","credential":"$password","urls":["turn:relay.example.invalid:3478?transport=udp"]}}"""
}
