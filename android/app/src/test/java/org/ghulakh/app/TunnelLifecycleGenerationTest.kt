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

    @Test
    fun staleWorkerCannotInvalidateNewerRun() {
        val lifecycle = TunnelLifecycleGeneration()
        val firstRun = lifecycle.begin()
        lifecycle.invalidate()
        val secondRun = lifecycle.begin()

        assertFalse(lifecycle.invalidate(firstRun))
        assertTrue(lifecycle.isCurrent(secondRun))
        assertTrue(lifecycle.invalidate(secondRun))
        assertFalse(lifecycle.isCurrent(secondRun))
    }
    @Test
    fun blockingSetupCannotPublishAfterStopInvalidatesItsGeneration() {
        val lifecycle = TunnelLifecycleGeneration()
        val generation = lifecycle.begin()
        val entered = java.util.concurrent.CountDownLatch(1)
        val release = java.util.concurrent.CountDownLatch(1)
        val published = java.util.concurrent.atomic.AtomicBoolean(false)
        val setup = Thread {
            entered.countDown()
            if (!release.await(1, java.util.concurrent.TimeUnit.SECONDS)) return@Thread
            if (lifecycle.isCurrent(generation)) published.set(true)
        }

        setup.start()
        assertTrue(entered.await(1, java.util.concurrent.TimeUnit.SECONDS))
        assertTrue(lifecycle.invalidate(generation))
        release.countDown()
        setup.join(1_000)

        assertFalse(setup.isAlive)
        assertFalse(published.get())
    }

}
