package org.ghulakh.app

import java.security.MessageDigest

/**
 * Bounded handling for an authenticated TURN Allocate 486 response.
 * Credentials are compared by digest only; raw credentials are never logged or retained.
 */
internal object TurnQuotaRetryPolicy {
    const val MAX_CONNECT_ATTEMPTS = 3
    const val MAX_REJECTED_FINGERPRINTS_PER_PATH = 16

    fun rememberRejectedFingerprint(
        rejectedByPath: MutableMap<Int, LinkedHashSet<String>>,
        pathId: Int,
        fingerprint: String,
    ) {
        val fingerprints = rejectedByPath.getOrPut(pathId) { linkedSetOf() }
        fingerprints.add(fingerprint)
        while (fingerprints.size > MAX_REJECTED_FINGERPRINTS_PER_PATH) {
            fingerprints.remove(fingerprints.first())
        }
    }

    fun wasRejectedForPath(
        rejectedByPath: Map<Int, Set<String>>,
        pathId: Int,
        fingerprint: String,
    ): Boolean = rejectedByPath[pathId]?.contains(fingerprint) == true

    fun fingerprint(credentialsJson: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(credentialsJson.toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { byte -> "%02x".format(byte) }
    }

    /**
     * [attemptIndex] is zero-based. A credential fingerprint is rejected at most once.
     */
    fun shouldRetry(
        attemptIndex: Int,
        rejectedFingerprint: String,
        rejectedFingerprints: MutableSet<String>,
    ): Boolean {
        if (attemptIndex + 1 >= MAX_CONNECT_ATTEMPTS) return false
        return rejectedFingerprints.add(rejectedFingerprint)
    }

    fun retryDelayMillis(attemptIndex: Int): Long =
        250L shl attemptIndex.coerceIn(0, 2)
}
