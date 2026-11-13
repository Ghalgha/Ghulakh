package org.ghulakh.app

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import org.json.JSONObject
import org.json.JSONArray

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
        val trimmed = credentialsJson.trim()
        if (trimmed.startsWith("[")) {
            val array = JSONArray(trimmed)
            require(array.length() in 2..10) { "TURN credential group size is invalid" }
            val fingerprints = (0 until array.length()).map { index ->
                fingerprintSingle(array.getJSONObject(index))
            }
            require(fingerprints.distinct().size == fingerprints.size) {
                "TURN credential group contains repeated credential sets"
            }
            val canonical = FingerprintWipingByteArrayOutputStream()
            try {
                DataOutputStream(canonical).use { output ->
                    fingerprints.sorted().forEach { value ->
                        val bytes = value.toByteArray(Charsets.US_ASCII)
                        try {
                            output.writeInt(bytes.size)
                            output.write(bytes)
                        } finally {
                            bytes.fill(0)
                        }
                    }
                }
                val encoded = canonical.toByteArray()
                return try { digest(encoded) } finally { encoded.fill(0) }
            } finally {
                canonical.wipe()
            }
        }
        return fingerprintSingle(JSONObject(trimmed))
    }


    /**
     * Returns one digest per independent TURN credential set. Group inputs must
     * contain 2–10 distinct members; singleton objects are handled by fingerprint().
     */
    fun credentialFingerprints(credentialsJson: String): List<String> {
        val trimmed = credentialsJson.trim()
        require(trimmed.startsWith("[")) { "TURN credential group must be a JSON array" }
        val array = JSONArray(trimmed)
        require(array.length() in 2..10) { "TURN credential group size is invalid" }
        val fingerprints = (0 until array.length()).map { index ->
            fingerprintSingle(array.getJSONObject(index))
        }
        require(fingerprints.distinct().size == fingerprints.size) {
            "TURN credential group contains repeated credential sets"
        }
        return fingerprints
    }

    /**
     * A group retry is accepted only when every member is new. The set is
     * mutated atomically after validating the whole group, so a rejected
     * candidate cannot partially reserve credentials.
     */
    fun shouldRetryGroup(
        attemptIndex: Int,
        credentialsJson: String,
        rejectedFingerprints: MutableSet<String>,
    ): Boolean = shouldRetryGroupFingerprints(
        attemptIndex,
        credentialFingerprints(credentialsJson),
        rejectedFingerprints,
    )

    fun shouldRetryGroupFingerprints(
        attemptIndex: Int,
        fingerprints: List<String>,
        rejectedFingerprints: MutableSet<String>,
    ): Boolean {
        if (attemptIndex + 1 >= MAX_CONNECT_ATTEMPTS) return false
        if (fingerprints.isEmpty() || fingerprints.any { it in rejectedFingerprints }) return false
        rejectedFingerprints.addAll(fingerprints)
        return true
    }

    private fun fingerprintSingle(root: JSONObject): String {
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
        val canonical = FingerprintWipingByteArrayOutputStream()
        try {
            DataOutputStream(canonical).use { output ->
                (listOf(username, credential) + endpoints).forEach { value ->
                    val bytes = value.toByteArray(Charsets.UTF_8)
                    try {
                        output.writeInt(bytes.size)
                        output.write(bytes)
                    } finally {
                        bytes.fill(0)
                    }
                }
            }
            val encoded = canonical.toByteArray()
            return try { digest(encoded) } finally { encoded.fill(0) }
        } finally {
            canonical.wipe()
        }
    }

    private fun digest(bytes: ByteArray): String {
        val hash = MessageDigest.getInstance("SHA-256").digest(bytes)
        return try {
            hash.joinToString("") { byte -> "%02x".format(byte) }
        } finally {
            hash.fill(0)
        }
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


private class FingerprintWipingByteArrayOutputStream : ByteArrayOutputStream() {
    fun wipe() {
        buf.fill(0)
        reset()
    }
}
