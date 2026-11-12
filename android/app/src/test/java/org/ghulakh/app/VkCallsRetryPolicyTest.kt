package org.ghulakh.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

class VkCallsRetryPolicyTest {
    @Test
    fun retriesNetworkFailuresAndTransientHttpStatuses() {
        assertTrue(VkCallsRetryPolicy.isRetryable(IOException("connection reset")))
        assertTrue(VkCallsRetryPolicy.isRetryable(VkCallsHttpException(408)))
        assertTrue(VkCallsRetryPolicy.isRetryable(VkCallsHttpException(429)))
        assertTrue(VkCallsRetryPolicy.isRetryable(VkCallsHttpException(500)))
        assertTrue(VkCallsRetryPolicy.isRetryable(VkCallsHttpException(599)))
    }

    @Test
    fun doesNotRetryPermanentHttpFailures() {
        assertFalse(VkCallsRetryPolicy.isRetryable(VkCallsHttpException(400)))
        assertFalse(VkCallsRetryPolicy.isRetryable(VkCallsHttpException(401)))
        assertFalse(VkCallsRetryPolicy.isRetryable(VkCallsHttpException(403)))
        assertFalse(VkCallsRetryPolicy.isRetryable(VkCallsHttpException(404)))
    }

    @Test
    fun retryDelayIsShortAndBounded() {
        assertEquals(250L, VkCallsRetryPolicy.delayMillis(0))
        assertEquals(500L, VkCallsRetryPolicy.delayMillis(1))
        assertEquals(500L, VkCallsRetryPolicy.delayMillis(2))
        assertEquals(500L, VkCallsRetryPolicy.delayMillis(Int.MAX_VALUE))
    }
}
