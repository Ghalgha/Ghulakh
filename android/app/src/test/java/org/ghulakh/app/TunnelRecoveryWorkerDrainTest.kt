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
    fun stopDuringRegisteredRecoveryWaitsBeforeFinishingCredentialBroker() {
        val recoveryLock = Any()
        val recoveryToken = AtomicBoolean(true)
        val registered = mutableListOf<Thread>()
        val supervisorMayRegister = CountDownLatch(1)
        val supervisorReady = CountDownLatch(1)
        val childStarted = CountDownLatch(1)
        val releaseChild = CountDownLatch(1)
        val brokerFinished = AtomicBoolean(false)
        val child = Thread {
            childStarted.countDown()
            var released = false
            while (!released) {
                try {
                    released = releaseChild.await(20, TimeUnit.MILLISECONDS)
                } catch (_: InterruptedException) {
                    // Model an in-flight native operation that does not finish
                    // merely because its Java worker was interrupted.
                }
            }
        }
        val supervisor = Thread {
            supervisorReady.countDown()
            supervisorMayRegister.await()
            synchronized(recoveryLock) {
                if (recoveryToken.get()) {
                    registered += child
                    child.start()
                }
            }
        }
        supervisor.start()
        assertTrue(supervisorReady.await(1, TimeUnit.SECONDS))

        val cleanup = Thread {
            awaitWorkerTermination(supervisor) {
                synchronized(recoveryLock) { registered.toList() }
            }
            brokerFinished.set(true)
        }
        cleanup.start()

        // The stop races with the supervisor's last possible registration.
        recoveryToken.set(false)
        supervisorMayRegister.countDown()
        assertTrue(childStarted.await(1, TimeUnit.SECONDS))
        child.interrupt()
        assertFalse(brokerFinished.get())

        releaseChild.countDown()
        cleanup.join(1_000)

        assertFalse(cleanup.isAlive)
        assertTrue(brokerFinished.get())
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
