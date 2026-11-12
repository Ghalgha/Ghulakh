package org.ghulakh.app

/**
 * Bounded exponential retry policy for independently recovered TURN paths.
 *
 * A small bounded jitter prevents paths that fail together from repeatedly
 * requesting fresh credentials and allocations in lockstep.
 */
internal object TurnRecoveryBackoffPolicy {
    private const val MAX_EXPONENT = 5
    private const val MAX_DELAY_MILLIS = 30_000L
    private const val MAX_JITTER_MILLIS = 500L

    fun delayMillis(failureCount: Int, jitterMillis: Long = 0L): Long {
        val exponent = failureCount.coerceIn(0, MAX_EXPONENT)
        val baseDelay = (1_000L shl exponent).coerceAtMost(MAX_DELAY_MILLIS)
        return baseDelay + jitterMillis.coerceIn(0L, MAX_JITTER_MILLIS)
    }
}
