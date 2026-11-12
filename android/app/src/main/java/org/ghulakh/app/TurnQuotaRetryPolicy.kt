package org.ghulakh.app

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import org.json.JSONObject

/**
 * Bounded handling for an authenticated TURN Allocate 486 response.
 * Credentials are compared by digest only; raw credentials are never logged or retained.
 */
internal object TurnQuotaRetryPolicy {
    const val MAX_CONNECT_ATTEMPTS = 3
    const val MAX_REJECTED_FINGERPRINTS_PER_GROUP = 64

    fun rememberRejectedFingerprint(
        rejected: LinkedHashSet<String>,
        fingerprint: String,
    ) {
        rejected.add(fingerprint)
        while (rejected.size > MAX_REJECTED_FINGERPRINTS_PER_GROUP) {
            rejected.remove(rejected.first())
        }
    }

    fun wasRejected(
        rejected: Set<String>,
        fingerprint: String,
    ): Boolean = fingerprint in rejected

    fun fingerprint(credentialsJson: String): String {
        val root = JSONObject(credentialsJson)
        val turnServer = root.optJSONObject("turn_server") ?: root
        val username = turnServer.getString("username")
        val credential = turnServer.getString("credential")
        require(username.isNotBlank() && credential.isNotBlank()) {
            "TURN credential identity is incomplete"
        }
        val urls = turnServer.getJSONArray("urls")
        require(urls.length() in 1..16) { "TURN credential endpoint count is invalid" }
        val endpoints = (0 until urls.length()).map { index ->
            urls.getString(index).also { require(it.isNotBlank()) { "TURN endpoint is empty" } }
        }.distinct().sorted()

        // Hash only credential identity, not JSON formatting or unrelated response metadata.
        // Length-prefixing makes the canonical byte sequence unambiguous.
        val canonical = ByteArrayOutputStream()
        DataOutputStream(canonical).use { output ->
            (listOf(username, credential) + endpoints).forEach { value ->
                val bytes = value.toByteArray(Charsets.UTF_8)
                output.writeInt(bytes.size)
                output.write(bytes)
            }
        }
        val digest = MessageDigest.getInstance("SHA-256").digest(canonical.toByteArray())
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
