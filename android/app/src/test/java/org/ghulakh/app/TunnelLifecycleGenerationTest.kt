package org.ghulakh.app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TunnelLifecycleGenerationTest {
    @Test
    fun stoppingAndRestartingInvalidatesEveryPreviousWorkerToken() {
        val lifecycle = TunnelLifecycleGeneration()
        val firstRun = lifecycle.begin()

        assertTrue(lifecycle.isCurrent(firstRun))

        lifecycle.invalidate()
        val secondRun = lifecycle.begin()

        assertFalse(lifecycle.isCurrent(firstRun))
        assertTrue(lifecycle.isCurrent(secondRun))
    }
}
