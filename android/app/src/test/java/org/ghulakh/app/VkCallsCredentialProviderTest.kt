package org.ghulakh.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Test

class VkCallsCredentialProviderTest {
    @Test
    fun parsedCredentialJsonContainersReleaseNestedStringReferences() {
        val json = org.json.JSONObject(
            """{"turn_server":{"username":"temporary-user","credential":"temporary-password","urls":["turn:relay.example?token=temporary-token"]},"metadata":["temporary-metadata"]}""",
        )
        val turnServer = json.getJSONObject("turn_server")
        val urls = turnServer.getJSONArray("urls")

        clearJsonStringReferences(json)

        assertEquals(0, json.length())
        assertEquals(0, turnServer.length())
        assertEquals("", urls.getString(0))
    }

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
        val groupCredentialsJson = "[$credentialJson,${credentialsJson("turn-user-2", "turn-password-secret-2")}]"
        val group = VkCallsCredentialGroup(
            turnCredentialsJson = groupCredentialsJson,
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

    @Test
    fun credentialSessionReleasesJsonAfterSingleHandoff() {
        val json = credentialsJson("session-user", "session-password")
        val session = VkCallsSession(
            turnCredentialsJson = json,
            apiUrl = "https://calls.example.invalid/",
            sessionKey = "session-key",
            conversationId = "conversation",
            finishAction = {},
        )

        assertEquals(json, session.takeTurnCredentialsJson())
        assertFalse(runCatching { session.takeTurnCredentialsJson() }.isSuccess)

        val abandoned = VkCallsSession(
            turnCredentialsJson = json,
            apiUrl = "https://calls.example.invalid/",
            sessionKey = "abandoned-session",
            conversationId = "conversation",
            finishAction = {},
        )
        abandoned.finish()
        assertFalse(runCatching { abandoned.takeTurnCredentialsJson() }.isSuccess)
    }

    @Test
    fun credentialGroupReleasesJsonAfterSingleNativeHandoff() {
        val initial = credentialsJson("initial-user", "initial-secret")
        val replacement = credentialsJson("replacement-user", "replacement-secret")
        val groupJson = "[$initial,$replacement]"
        val owner = VkCallsSession(
            turnCredentialsJson = initial,
            apiUrl = "https://calls.example.invalid/",
            sessionKey = "owner-session",
            conversationId = "conversation",
            finishAction = {},
        )
        val broker = VkCallsCredentialProvider.CredentialBroker(
            accessToken = "access-token",
            conversationId = "conversation",
            initialCredentialsJson = initial,
            sessionFetcher = { error("not used") },
        )
        val group = VkCallsCredentialGroup(groupJson, owner, broker)

        assertEquals(groupJson, group.takeTurnCredentialsJson())
        assertFalse(runCatching { group.takeTurnCredentialsJson() }.isSuccess)

        val abandoned = VkCallsCredentialGroup(groupJson, owner, broker)
        abandoned.finish()
        assertFalse(runCatching { abandoned.takeTurnCredentialsJson() }.isSuccess)
    }

    @Test
    fun credentialBrokerBoundsRetainedAuxiliarySessions() {
        val initial = credentialsJson("initial-user", "initial-secret")
        var fetched = 0
        var finished = 0
        val broker = VkCallsCredentialProvider.CredentialBroker(
            accessToken = "access-token",
            conversationId = "conversation",
            initialCredentialsJson = initial,
            sessionFetcher = {
                fetched += 1
                VkCallsSession(
                    turnCredentialsJson = credentialsJson("user-$fetched", "secret-$fetched"),
                    apiUrl = "https://calls.example.invalid/",
                    sessionKey = "session-$fetched",
                    conversationId = "conversation",
                    finishAction = { finished += 1 },
                )
            },
        )

        repeat(127) { broker.obtainCredentials() }
        assertFalse(runCatching { broker.obtainCredentials() }.isSuccess)
        broker.finish()
        assertEquals(128, fetched)
        assertEquals(128, finished)
    }

 
    @Test
    fun credentialBrokerClosesSessionReturnedAfterConcurrentFinish() {
        val initial = credentialsJson("initial-user", "initial-secret")
        val fetchStarted = java.util.concurrent.CountDownLatch(1)
        val allowFetchToReturn = java.util.concurrent.CountDownLatch(1)
        val finishedSessions = java.util.concurrent.atomic.AtomicInteger()
        val broker = VkCallsCredentialProvider.CredentialBroker(
            accessToken = "access-token-that-must-be-released",
            conversationId = "conversation",
            initialCredentialsJson = initial,
            sessionFetcher = {
                fetchStarted.countDown()
                check(allowFetchToReturn.await(5, java.util.concurrent.TimeUnit.SECONDS))
                VkCallsSession(
                    turnCredentialsJson = credentialsJson("late-user", "late-secret"),
                    apiUrl = "https://calls.example.invalid/",
                    sessionKey = "late-session-key",
                    conversationId = "conversation",
                    finishAction = { finishedSessions.incrementAndGet() },
                )
            },
        )
        val result = java.util.concurrent.atomic.AtomicReference<Throwable?>()
        val worker = Thread {
            runCatching { broker.obtainCredentials() }.onFailure { result.set(it) }
        }
        worker.start()
        assertEquals(true, fetchStarted.await(5, java.util.concurrent.TimeUnit.SECONDS))
        broker.finish()
        allowFetchToReturn.countDown()
        worker.join(5_000)

        assertFalse(worker.isAlive)
        assertFalse(result.get() == null)
        assertEquals(1, finishedSessions.get())
        assertFalse(runCatching { broker.obtainCredentials() }.isSuccess)
    }

    @Test
    fun concurrentCredentialFetchesAreAllClosedWhenBrokerFinishes() {
        val workers = 8
        val fetchesStarted = java.util.concurrent.CountDownLatch(workers)
        val releaseFetches = java.util.concurrent.CountDownLatch(1)
        val finishedSessions = java.util.concurrent.atomic.AtomicInteger()
        val fetchCount = java.util.concurrent.atomic.AtomicInteger()
        val broker = VkCallsCredentialProvider.CredentialBroker(
            accessToken = "access-token",
            conversationId = "conversation",
            initialCredentialsJson = credentialsJson("initial-user", "initial-secret"),
            sessionFetcher = {
                val index = fetchCount.incrementAndGet()
                fetchesStarted.countDown()
                check(releaseFetches.await(5, java.util.concurrent.TimeUnit.SECONDS))
                VkCallsSession(
                    turnCredentialsJson = credentialsJson("late-user-$index", "late-secret-$index"),
                    apiUrl = "https://calls.example.invalid",
                    sessionKey = "session-key",
                    conversationId = "conversation",
                    finishAction = { finishedSessions.incrementAndGet() },
                )
            },
        )
        val executor = java.util.concurrent.Executors.newFixedThreadPool(workers)
        val results = (0 until workers).map {
            executor.submit<Boolean> {
                runCatching { broker.obtainCredentials() }.isFailure
            }
        }

        assertEquals(true, fetchesStarted.await(5, java.util.concurrent.TimeUnit.SECONDS))
        broker.finish()
        releaseFetches.countDown()
        executor.shutdown()
        assertEquals(true, executor.awaitTermination(10, java.util.concurrent.TimeUnit.SECONDS))
        assertEquals(workers, results.count { it.get() })
        assertEquals(workers, finishedSessions.get())
        assertEquals(workers, fetchCount.get())
    }

    private fun credentialsJson(username: String, password: String): String =
        """{"turn_server":{"username":"$username","credential":"$password","urls":["turn:relay.example.invalid:3478?transport=udp"]}}"""
}
