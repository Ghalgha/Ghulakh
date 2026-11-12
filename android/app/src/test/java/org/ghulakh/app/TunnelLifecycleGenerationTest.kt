package org.ghulakh.app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

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
    fun concurrentStopAndSessionCompletionInvalidateOnlyTheirOwnGeneration() {
        val lifecycle = TunnelLifecycleGeneration()
        val oldGeneration = lifecycle.begin()
        val ready = CountDownLatch(12)
        val start = CountDownLatch(1)
        val invalidations = AtomicInteger(0)
        val workers = List(12) {
            Thread {
                ready.countDown()
                start.await()
                if (lifecycle.invalidate(oldGeneration)) invalidations.incrementAndGet()
            }.apply { start() }
        }

        assertTrue(ready.await(1, TimeUnit.SECONDS))
        start.countDown()
        workers.forEach { it.join(1_000) }

        assertTrue(workers.none { it.isAlive })
        assertTrue(invalidations.get() == 1)
        val newGeneration = lifecycle.begin()

        // A late completion from the old run must not stop the restarted run.
        assertFalse(lifecycle.invalidate(oldGeneration))
        assertTrue(lifecycle.isCurrent(newGeneration))
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
