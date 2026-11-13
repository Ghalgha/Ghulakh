package org.ghulakh.app

import org.junit.Assert.assertEquals
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

    private fun credentialsJson(username: String, password: String): String =
        """{"turn_server":{"username":"$username","credential":"$password","urls":["turn:relay.example.invalid:3478?transport=udp"]}}"""
}
