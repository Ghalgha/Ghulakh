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
        val first = TurnQuotaRetryPolicy.fingerprint("""{"username":"first","credential":"secret-a"}""")
        val second = TurnQuotaRetryPolicy.fingerprint("""{"username":"second","credential":"secret-b"}""")

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
        val credentials = """{"username":"user","credential":"private-value"}"""
        val fingerprint = TurnQuotaRetryPolicy.fingerprint(credentials)

        assertEquals(fingerprint, TurnQuotaRetryPolicy.fingerprint(credentials))
        assertNotEquals(credentials, fingerprint)
        assertFalse(fingerprint.contains("private-value"))
    }

    @Test
    fun retryDelayIsBounded() {
        assertEquals(250L, TurnQuotaRetryPolicy.retryDelayMillis(0))
        assertEquals(500L, TurnQuotaRetryPolicy.retryDelayMillis(1))
        assertEquals(1_000L, TurnQuotaRetryPolicy.retryDelayMillis(2))
        assertEquals(1_000L, TurnQuotaRetryPolicy.retryDelayMillis(Int.MAX_VALUE))
        assertEquals(250L, TurnQuotaRetryPolicy.retryDelayMillis(Int.MIN_VALUE))
    }
}
