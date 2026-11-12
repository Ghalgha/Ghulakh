package org.ghulakh.app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

class TunnelRecoveryWorkerDrainTest {
    @Test
    fun waitsForSupervisorAndEveryRegisteredPathWorker() {
        val childStarted = CountDownLatch(1)
        val releaseChild = CountDownLatch(1)
        val child = Thread {
            childStarted.countDown()
            releaseChild.await()
        }
        val supervisor = Thread { child.start() }
        supervisor.start()

        val returned = AtomicBoolean(false)
        val waiter = Thread {
            awaitWorkerTermination(supervisor) { listOf(child) }
            returned.set(true)
        }
        waiter.start()

        assertTrue(childStarted.await(1, TimeUnit.SECONDS))
        assertFalse(returned.get())
        releaseChild.countDown()
        waiter.join(1_000)

        assertFalse(waiter.isAlive)
        assertTrue(returned.get())
    }

    @Test
    fun preservesInterruptAfterAllRecoveryWorkersExit() {
        val childStarted = CountDownLatch(1)
        val releaseChild = CountDownLatch(1)
        val child = Thread {
            childStarted.countDown()
            releaseChild.await()
        }
        val supervisor = Thread { child.start() }
        supervisor.start()

        val interruptRestored = AtomicBoolean(false)
        val waiter = Thread {
            awaitWorkerTermination(supervisor) { listOf(child) }
            interruptRestored.set(Thread.currentThread().isInterrupted)
        }
        waiter.start()

        assertTrue(childStarted.await(1, TimeUnit.SECONDS))
        waiter.interrupt()
        assertFalse(interruptRestored.get())
        releaseChild.countDown()
        waiter.join(1_000)

        assertFalse(waiter.isAlive)
        assertTrue(interruptRestored.get())
    }
}
