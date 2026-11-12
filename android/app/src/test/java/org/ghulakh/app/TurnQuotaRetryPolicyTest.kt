package org.ghulakh.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TurnQuotaRetryPolicyTest {
    @Test
    fun retriesOnlyWithNewCredentialFingerprintsAndWithinBound() {
        val rejected = mutableSetOf<String>()
        val first = TurnQuotaRetryPolicy.fingerprint(
            """{"turn_server":{"username":"first","credential":"secret-a","urls":["turn:relay.example:3478"]}}""",
        )
        val second = TurnQuotaRetryPolicy.fingerprint(
            """{"turn_server":{"username":"second","credential":"secret-b","urls":["turn:relay.example:3478"]}}""",
        )

        assertTrue(TurnQuotaRetryPolicy.shouldRetry(0, first, rejected))
        assertFalse(TurnQuotaRetryPolicy.shouldRetry(1, first, rejected))
        assertTrue(TurnQuotaRetryPolicy.shouldRetry(1, second, rejected))
        assertFalse(
            TurnQuotaRetryPolicy.shouldRetry(
                TurnQuotaRetryPolicy.MAX_CONNECT_ATTEMPTS - 1,
                "third",
                rejected,
            ),
        )
    }

    @Test
    fun fingerprintsAreStableAndDoNotExposeCredentialText() {
        val credentials = """{"turn_server":{"username":"user","credential":"private-value","urls":["turn:relay.example:3478","turn:backup.example:3478"]}}"""
        val reordered = """{"metadata":"rotated","turn_server":{"urls":["turn:backup.example:3478","turn:relay.example:3478"],"credential":"private-value","username":"user"}}"""
        val fingerprint = TurnQuotaRetryPolicy.fingerprint(credentials)

        assertEquals(fingerprint, TurnQuotaRetryPolicy.fingerprint(credentials))
        assertEquals(fingerprint, TurnQuotaRetryPolicy.fingerprint(reordered))
        assertNotEquals(credentials, fingerprint)
        assertFalse(fingerprint.contains("private-value"))
        assertNotEquals(
            fingerprint,
            TurnQuotaRetryPolicy.fingerprint(
                """{"turn_server":{"username":"user","credential":"different-secret","urls":["turn:relay.example:3478","turn:backup.example:3478"]}}""",
            ),
        )
    }


    @Test
    fun credentialGroupsAreOrderIndependentAndRejectPreviouslyRejectedMembers() {
        val first = """{"turn_server":{"username":"u1","credential":"p1","urls":["turn:a.example:3478"]}}"""
        val second = """{"turn_server":{"username":"u2","credential":"p2","urls":["turn:b.example:3478"]}}"""
        val third = """{"turn_server":{"username":"u3","credential":"p3","urls":["turn:c.example:3478"]}}"""
        val group = "[$first,$second]"
        val reordered = "[$second,$first]"
        assertEquals(
            TurnQuotaRetryPolicy.fingerprint(group),
            TurnQuotaRetryPolicy.fingerprint(reordered),
        )

        val rejected = mutableSetOf<String>()
        assertTrue(TurnQuotaRetryPolicy.shouldRetryGroup(0, group, rejected))
        assertFalse(TurnQuotaRetryPolicy.shouldRetryGroup(1, "[$third,$first]", rejected))
        assertTrue(TurnQuotaRetryPolicy.shouldRetryGroup(1, "[$third]", rejected).not())
    }

    @Test
    fun credentialGroupsRejectDuplicateMembers() {
        val credential = """{"turn_server":{"username":"u","credential":"p","urls":["turn:a.example:3478"]}}"""
        try {
            TurnQuotaRetryPolicy.credentialFingerprints("[$credential,$credential]")
            throw AssertionError("duplicate credential set was accepted")
        } catch (_: IllegalArgumentException) {
            // Expected: one allocation credential cannot be reused across paths.
        }
    }

    @Test
    fun retryDelayIsBounded() {
        assertEquals(250L, TurnQuotaRetryPolicy.retryDelayMillis(0))
        assertEquals(500L, TurnQuotaRetryPolicy.retryDelayMillis(1))
        assertEquals(1_000L, TurnQuotaRetryPolicy.retryDelayMillis(2))
        assertEquals(1_000L, TurnQuotaRetryPolicy.retryDelayMillis(Int.MAX_VALUE))
        assertEquals(250L, TurnQuotaRetryPolicy.retryDelayMillis(Int.MIN_VALUE))
    }
    @Test
    fun rejectedCredentialsAreTrackedAcrossPathsWithBoundedHistory() {
        val rejected = linkedSetOf<String>()
        TurnQuotaRetryPolicy.rememberRejectedFingerprint(rejected, "shared-credential")
        assertTrue(TurnQuotaRetryPolicy.wasRejected(rejected, "shared-credential"))

        // A fingerprint rejected while recovering one path is also rejected by every other path.
        assertTrue(TurnQuotaRetryPolicy.wasRejected(rejected, "shared-credential"))

        repeat(TurnQuotaRetryPolicy.MAX_REJECTED_FINGERPRINTS_PER_GROUP + 1) { index ->
            TurnQuotaRetryPolicy.rememberRejectedFingerprint(rejected, "credential-$index")
        }
        assertEquals(TurnQuotaRetryPolicy.MAX_REJECTED_FINGERPRINTS_PER_GROUP, rejected.size)
        assertFalse(TurnQuotaRetryPolicy.wasRejected(rejected, "credential-0"))
    }

}


class VkCallsSessionIdempotenceTest {
    @Test
    fun concurrentFinishRequestsRunCleanupOnlyOnce() {
        val session = VkCallsSession(
            turnCredentialsJson = "{}",
            apiUrl = "https://calls.example.invalid/fb.do",
            sessionKey = "test-session-key",
            conversationId = "test-conversation",
        )
        val cleanupCalls = java.util.concurrent.atomic.AtomicInteger(0)
        val callers = List(16) {
            Thread {
                session.finishOnce { cleanupCalls.incrementAndGet() }
            }
        }

        callers.forEach(Thread::start)
        callers.forEach(Thread::join)

        assertEquals(1, cleanupCalls.get())
    }

    @Test
    fun repeatedFinishRequestsDoNotRepeatCleanup() {
        val session = VkCallsSession(
            turnCredentialsJson = "{}",
            apiUrl = "https://calls.example.invalid/fb.do",
            sessionKey = "test-session-key",
            conversationId = "test-conversation",
        )
        val cleanupCalls = java.util.concurrent.atomic.AtomicInteger(0)

        repeat(3) {
            session.finishOnce { cleanupCalls.incrementAndGet() }
        }

        assertEquals(1, cleanupCalls.get())
    }
}
