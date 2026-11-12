package org.ghulakh.app

import java.util.concurrent.atomic.AtomicLong

/**
 * Monotonic ownership token for one VPN service run. A stale worker cannot
 * become current again when the service is stopped and subsequently restarted.
 */
internal class TunnelLifecycleGeneration {
    private val current = AtomicLong(0)

    fun begin(): Long = current.incrementAndGet()

    fun invalidate(): Long = current.incrementAndGet()

    fun isCurrent(generation: Long): Boolean = current.get() == generation
}
