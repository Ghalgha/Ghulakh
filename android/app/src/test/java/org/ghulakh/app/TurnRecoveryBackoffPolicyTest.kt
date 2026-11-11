package org.ghulakh.app

import org.junit.Assert.assertEquals
import org.junit.Test

class TurnRecoveryBackoffPolicyTest {
    @Test
    fun exponentialDelayIsBoundedAtThirtySeconds() {
        assertEquals(1L, TurnRecoveryBackoffPolicy.delaySeconds(0))
        assertEquals(2L, TurnRecoveryBackoffPolicy.delaySeconds(1))
        assertEquals(4L, TurnRecoveryBackoffPolicy.delaySeconds(2))
        assertEquals(8L, TurnRecoveryBackoffPolicy.delaySeconds(3))
        assertEquals(16L, TurnRecoveryBackoffPolicy.delaySeconds(4))
        assertEquals(30L, TurnRecoveryBackoffPolicy.delaySeconds(5))
        assertEquals(30L, TurnRecoveryBackoffPolicy.delaySeconds(6))
        assertEquals(30L, TurnRecoveryBackoffPolicy.delaySeconds(Int.MAX_VALUE))
    }

    @Test
    fun negativeFailureCountUsesInitialDelay() {
        assertEquals(1L, TurnRecoveryBackoffPolicy.delaySeconds(-1))
        assertEquals(1L, TurnRecoveryBackoffPolicy.delaySeconds(Int.MIN_VALUE))
    }
}
