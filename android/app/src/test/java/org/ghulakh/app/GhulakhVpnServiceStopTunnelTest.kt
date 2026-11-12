package org.ghulakh.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.lang.reflect.Field
import java.lang.reflect.Method
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class GhulakhVpnServiceStopTunnelTest {
    @Test
    fun stopTunnelDrainsRegisteredRecoveryBeforeSessionCompletion() {
        val service = Robolectric.buildService(GhulakhVpnService::class.java).create().get()
        try {
            val generation = beginRunningGeneration(service)
            val token = AtomicBoolean(true)
            val recoveryLock = field(service, "recoveryLock").get(service)
            @Suppress("UNCHECKED_CAST")
            val tokens = field(service, "recoveryTokens").get(service) as MutableSet<AtomicBoolean>
            @Suppress("UNCHECKED_CAST")
            val pathWorkers = field(service, "pathRecoveryThreads").get(service)
                as MutableMap<Pair<AtomicBoolean, Int>, Thread>
            val supervisorStarted = CountDownLatch(1)
            val childStarted = CountDownLatch(1)
            val releaseSupervisor = CountDownLatch(1)
            val releaseChild = CountDownLatch(1)
            val supervisorInterrupted = AtomicBoolean(false)
            val childInterrupted = AtomicBoolean(false)
            val supervisorInterruptObserved = CountDownLatch(1)
            val childInterruptObserved = CountDownLatch(1)
            val brokerFinished = AtomicBoolean(false)

            val supervisor = Thread {
                supervisorStarted.countDown()
                awaitIgnoringInterrupt(releaseSupervisor, supervisorInterrupted, supervisorInterruptObserved)
            }
            val child = Thread {
                childStarted.countDown()
                awaitIgnoringInterrupt(releaseChild, childInterrupted, childInterruptObserved)
            }
            tokens.add(token)
            pathWorkers[token to 7] = child
            field(service, "recoveryWorker").set(service, supervisor)
            supervisor.start()
            child.start()

            assertTrue(supervisorStarted.await(1, TimeUnit.SECONDS))
            assertTrue(childStarted.await(1, TimeUnit.SECONDS))

            assertTrue(invokeStopTunnel(service, generation))
            assertFalse(token.get())

            val completion = Thread {
                awaitWorkerTermination(supervisor) {
                    synchronized(recoveryLock) { pathWorkers.values.toList() }
                }
                brokerFinished.set(true)
            }
            completion.start()

            assertTrue(supervisorInterruptObserved.await(1, TimeUnit.SECONDS))
            assertTrue(childInterruptObserved.await(1, TimeUnit.SECONDS))
            assertTrue(supervisorInterrupted.get())
            assertTrue(childInterrupted.get())
            assertFalse(brokerFinished.get())

            releaseSupervisor.countDown()
            releaseChild.countDown()
            completion.join(1_000)

            assertFalse(completion.isAlive)
            assertTrue(brokerFinished.get())
            assertFalse(invokeStopTunnel(service, generation))
        } finally {
            serviceStop(service)
        }
    }

    @Test
    fun concurrentStopAndSessionCompletionCanInvalidateOnlyOnce() {
        val service = Robolectric.buildService(GhulakhVpnService::class.java).create().get()
        try {
            val generation = beginRunningGeneration(service)
            val ready = CountDownLatch(2)
            val start = CountDownLatch(1)
            val outcomes = java.util.Collections.synchronizedList(mutableListOf<Boolean>())
            val callers = List(2) {
                Thread {
                    ready.countDown()
                    start.await()
                    outcomes.add(invokeStopTunnel(service, generation))
                }.apply { start() }
            }

            assertTrue(ready.await(1, TimeUnit.SECONDS))
            start.countDown()
            callers.forEach { it.join(1_000) }

            assertTrue(callers.none { it.isAlive })
            assertEquals(listOf(true, false), outcomes.sortedByDescending { it })
            assertFalse(invokeStopTunnel(service, generation))
        } finally {
            serviceStop(service)
        }
    }

    private fun beginRunningGeneration(service: GhulakhVpnService): Long {
        val lifecycle = field(service, "lifecycleGeneration").get(service) as TunnelLifecycleGeneration
        (field(service, "running").get(service) as AtomicBoolean).set(true)
        return lifecycle.begin()
    }

    private fun invokeStopTunnel(service: GhulakhVpnService, generation: Long): Boolean =
        stopMethod.invoke(service, generation) as Boolean

    private fun serviceStop(service: GhulakhVpnService) {
        runCatching { stopMethod.invoke(service, *arrayOf<Any?>(null)) }
    }

    private fun field(instance: Any, name: String): Field =
        instance.javaClass.getDeclaredField(name).apply { isAccessible = true }

    private fun awaitIgnoringInterrupt(
        latch: CountDownLatch,
        interrupted: AtomicBoolean,
        interruptObserved: CountDownLatch,
    ) {
        while (true) {
            try {
                latch.await()
                return
            } catch (_: InterruptedException) {
                interrupted.set(true)
                interruptObserved.countDown()
            }
        }
    }

    companion object {
        private val stopMethod: Method = GhulakhVpnService::class.java
            .getDeclaredMethod("stopTunnel", java.lang.Long::class.java)
            .apply { isAccessible = true }
    }
}
