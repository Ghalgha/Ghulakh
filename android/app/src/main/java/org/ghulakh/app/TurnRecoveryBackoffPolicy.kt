package org.ghulakh.app

/**
 * Bounded exponential retry policy for independently recovered TURN paths.
 *
 * The failure count is supplied by the path owner, so a successful path reset
 * does not affect the retry schedule of another path.
 */
internal object TurnRecoveryBackoffPolicy {
    private const val MAX_EXPONENT = 5
    private const val MAX_DELAY_SECONDS = 30L

    fun delaySeconds(failureCount: Int): Long {
        val exponent = failureCount.coerceIn(0, MAX_EXPONENT)
        return (1L shl exponent).coerceAtMost(MAX_DELAY_SECONDS)
    }
}
