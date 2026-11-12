package org.ghulakh.app

import org.junit.Assert.assertEquals
import org.junit.Test

class TurnRecoveryBackoffPolicyTest {
    @Test
    fun exponentialDelayIsBoundedAtThirtySecondsBeforeJitter() {
        assertEquals(1_000L, TurnRecoveryBackoffPolicy.delayMillis(0))
        assertEquals(2_000L, TurnRecoveryBackoffPolicy.delayMillis(1))
        assertEquals(4_000L, TurnRecoveryBackoffPolicy.delayMillis(2))
        assertEquals(8_000L, TurnRecoveryBackoffPolicy.delayMillis(3))
        assertEquals(16_000L, TurnRecoveryBackoffPolicy.delayMillis(4))
        assertEquals(30_000L, TurnRecoveryBackoffPolicy.delayMillis(5))
        assertEquals(30_000L, TurnRecoveryBackoffPolicy.delayMillis(6))
        assertEquals(30_000L, TurnRecoveryBackoffPolicy.delayMillis(Int.MAX_VALUE))
    }

    @Test
    fun negativeFailureCountUsesInitialDelay() {
        assertEquals(1_000L, TurnRecoveryBackoffPolicy.delayMillis(-1))
        assertEquals(1_000L, TurnRecoveryBackoffPolicy.delayMillis(Int.MIN_VALUE))
    }

    @Test
    fun jitterIsBoundedAndAddedWithoutChangingTheBaseSchedule() {
        assertEquals(1_000L, TurnRecoveryBackoffPolicy.delayMillis(0, -1))
        assertEquals(1_250L, TurnRecoveryBackoffPolicy.delayMillis(0, 250))
        assertEquals(1_500L, TurnRecoveryBackoffPolicy.delayMillis(0, 900))
        assertEquals(30_500L, TurnRecoveryBackoffPolicy.delayMillis(5, 500))
        assertEquals(30_500L, TurnRecoveryBackoffPolicy.delayMillis(Int.MAX_VALUE, Long.MAX_VALUE))
    }
}
