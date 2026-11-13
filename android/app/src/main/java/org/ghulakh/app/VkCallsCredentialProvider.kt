package org.ghulakh.app

import org.json.JSONObject
import org.json.JSONArray
import java.io.ByteArrayOutputStream
import javax.net.ssl.HttpsURLConnection
import java.net.URL
import java.io.IOException
import java.net.URLEncoder
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

class VkCallsSession(
    turnCredentialsJson: String,
    internal val apiUrl: String,
    internal val sessionKey: String,
    internal val conversationId: String,
    private val finishAction: (() -> Unit)? = null,
) {
    private var pendingTurnCredentialsJson: String? = turnCredentialsJson
    private val finished = AtomicBoolean(false)

    internal fun takeTurnCredentialsJson(): String = synchronized(this) {
        pendingTurnCredentialsJson.also { pendingTurnCredentialsJson = null }
            ?: error("TURN credentials have already been consumed")
    }

    fun finish() {
        finishOnce {
            finishAction?.invoke() ?: VkCallsCredentialProvider.finishConversation(
                apiUrl,
                sessionKey,
                conversationId,
            )
        }
    }

    internal fun finishOnce(action: () -> Unit) {
        if (finished.compareAndSet(false, true)) action()
    }

    override fun toString(): String =
        "VkCallsSession(turnCredentialsJson=<redacted>, apiUrl=<redacted>, sessionKey=<redacted>, conversationId=<redacted>)"
}

internal class VkCallsCredentialGroup(
    turnCredentialsJson: String,
    val ownerSession: VkCallsSession,
    internal val credentialBroker: VkCallsCredentialProvider.CredentialBroker,
) {
    private var pendingTurnCredentialsJson: String? = turnCredentialsJson
    internal val credentialFingerprints: List<String> =
        TurnQuotaRetryPolicy.credentialFingerprints(turnCredentialsJson)

    internal fun takeTurnCredentialsJson(): String = synchronized(this) {
        pendingTurnCredentialsJson.also { pendingTurnCredentialsJson = null }
            ?: error("TURN credential group has already been consumed")
    }

    fun finish() {
        credentialBroker.finish()
        ownerSession.finish()
    }

    override fun toString(): String =
        "VkCallsCredentialGroup(turnCredentialsJson=<redacted>, ownerSession=<redacted>, credentialBroker=<redacted>)"
}

/**
 * Obtains short-lived TURN credentials using the authenticated VK Calls flow.
 * It uses ordinary HTTPS and does not emulate a browser TLS fingerprint.
 */
object VkCallsCredentialProvider {
    private const val VK_API_VERSION = "5.285"
    private const val VK_APP_ID = "6287487"
    private const val OK_APPLICATION_KEY = "CGMMEJLGDIHBABABA"
    private const val DEFAULT_OK_API = "https://calls.okcdn.ru/fb.do"
    private const val MAX_RESPONSE_BYTES = 512 * 1024
    private const val CONNECT_TIMEOUT_MS = 8_000
    private const val READ_TIMEOUT_MS = 8_000
    private const val MAX_TRACKED_CREDENTIAL_SETS = 128

    fun obtain(accessToken: String): VkCallsSession {
        require(accessToken.isNotBlank()) { "VK access token is empty" }
        require(accessToken.length <= 16_384) { "VK access token is too long" }

        val deviceId = UUID.randomUUID().toString()
        val tokenResponse = postFormWithRetry(
            "https://api.vk.ru/method/messages.getCallToken?v=$VK_API_VERSION&client_id=$VK_APP_ID",
            mapOf(
                "env" to "production",
                "access_token" to accessToken,
            ),
        )
        val tokenData = tokenResponse.getJSONObject("response")
        val callToken = tokenData.getString("token")
        require(callToken.isNotBlank()) { "VK did not return a Calls token" }
        val apiUrl = validateApiUrl(tokenData.optString("api_base_url").ifBlank { DEFAULT_OK_API })

        val sessionData = JSONObject()
            .put("auth_token", callToken)
            .put("version", 3)
            .put("device_id", deviceId)
            .put("client_version", "1.0.1")
            .toString()
        val login = postFormWithRetry(
            apiUrl,
            mapOf(
                "session_data" to sessionData,
                "device_id" to deviceId,
                "verification_supported" to "true",
                "verification_supported_v" to "1",
                "client" to "test",
                "gen_token" to "true",
                "method" to "auth.anonymLogin",
                "format" to "JSON",
                "application_key" to OK_APPLICATION_KEY,
            ),
        )
        val sessionKey = login.getString("session_key")
        require(sessionKey.isNotBlank()) { "Calls backend returned an empty session key" }

        val conversationId = UUID.randomUUID().toString()
        val payload = JSONObject()
            .put("is_video", true)
            .put("with_join_link", true)
            .put("join_by_link", true)
            .put("community_user_id", 0)
            .put("caller_app_id", VK_APP_ID)
            .toString()
        try {
            val started = postForm(
                apiUrl,
                mapOf(
                    "conversationId" to conversationId,
                    "isVideo" to "true",
                    "protocolVersion" to "5",
                    "createJoinLink" to "true",
                    "payload" to payload,
                    "onlyAdminCanShareMovie" to "false",
                    "externalIds" to "",
                    "method" to "vchat.startConversation",
                    "format" to "JSON",
                    "application_key" to OK_APPLICATION_KEY,
                    "session_key" to sessionKey,
                ),
            )
            checkApiError(started)
            require(started.optString("join_link").isNotBlank()) {
                "Calls backend did not return a join link"
            }

            val parameters = postFormWithRetry(
                apiUrl,
                mapOf(
                    "conversationId" to conversationId,
                    "method" to "vchat.getConversationParams",
                    "format" to "JSON",
                    "application_key" to OK_APPLICATION_KEY,
                    "session_key" to sessionKey,
                ),
            )
            checkApiError(parameters)
            val turnServer = parameters.optJSONObject("turn_server")
                ?: parameters.optJSONObject("response")?.optJSONObject("turn_server")
                ?: throw IllegalStateException("Calls backend response has no turn_server object")
            require(turnServer.optString("username").isNotBlank()) {
                "VK Calls returned an empty TURN username"
            }
            require(turnServer.optString("credential").isNotBlank()) {
                "VK Calls returned an empty TURN credential"
            }
            val urls = turnServer.optJSONArray("urls")
                ?: throw IllegalStateException("VK Calls returned no TURN URLs")
            require(urls.length() in 1..16) { "VK Calls returned an invalid TURN URL count" }
            val credentialsJson = JSONObject().put("turn_server", turnServer).toString()
            return VkCallsSession(
                turnCredentialsJson = credentialsJson,
                apiUrl = apiUrl,
                sessionKey = sessionKey,
                conversationId = conversationId,
            )
        } catch (error: Throwable) {
            runCatching { finishConversation(apiUrl, sessionKey, conversationId) }
            throw error
        }
    }


    internal class CredentialBroker(
        private val accessToken: String,
        private val conversationId: String,
        initialCredentialsJson: String,
        private val sessionFetcher: (() -> VkCallsSession)? = null,
    ) {
        private val lock = Any()
        private val issuedFingerprints = linkedSetOf(
            TurnQuotaRetryPolicy.fingerprint(initialCredentialsJson),
        )
        private val sessions = mutableListOf<VkCallsSession>()
        private var finished = false

        fun obtainCredentials(): String {
            val session = sessionFetcher?.invoke()
                ?: VkCallsCredentialProvider.obtainConversationSession(accessToken, conversationId)
            try {
                val credentialsJson = session.takeTurnCredentialsJson()
                val fingerprint = TurnQuotaRetryPolicy.fingerprint(credentialsJson)
                synchronized(lock) {
                    check(!finished) { "VK Calls credential broker is already finished" }
                    check(issuedFingerprints.size < MAX_TRACKED_CREDENTIAL_SETS) {
                        "VK Calls credential set limit reached"
                    }
                    require(issuedFingerprints.add(fingerprint)) {
                        "VK Calls returned a repeated TURN credential set"
                    }
                    sessions.add(session)
                }
                return credentialsJson
            } catch (error: Throwable) {
                runCatching { session.finish() }
                throw error
            }
        }

        fun finish() {
            val pending = synchronized(lock) {
                if (finished) return
                finished = true
                issuedFingerprints.clear()
                sessions.toList().also { sessions.clear() }
            }
            pending.forEach { session ->
                runCatching { session.finish() }
            }
        }
    }

    /**
     * Creates one Calls conversation and obtains a distinct TURN credential set
     * for each independent allocation through separate anonymous account sessions.
     */
    internal fun obtainGroup(accessToken: String, pathCount: Int): VkCallsCredentialGroup {
        require(pathCount in 2..10) { "TURN path count must be between 2 and 10" }
        val owner = obtain(accessToken)
        val initialCredentialsJson = owner.takeTurnCredentialsJson()
        val broker = CredentialBroker(accessToken, owner.conversationId, initialCredentialsJson)
        try {
            val array = JSONArray().put(JSONObject(initialCredentialsJson))
            repeat(pathCount - 1) { array.put(JSONObject(broker.obtainCredentials())) }
            return VkCallsCredentialGroup(array.toString(), owner, broker)
        } catch (error: Throwable) {
            broker.finish()
            runCatching { owner.finish() }
            throw error
        }
    }

    private fun obtainConversationSession(accessToken: String, conversationId: String): VkCallsSession {
        val deviceId = UUID.randomUUID().toString()
        val tokenResponse = postFormWithRetry(
            "https://api.vk.ru/method/messages.getCallToken?v=$VK_API_VERSION&client_id=$VK_APP_ID",
            mapOf("env" to "production", "access_token" to accessToken),
        )
        val tokenData = tokenResponse.getJSONObject("response")
        val callToken = tokenData.getString("token")
        require(callToken.isNotBlank()) { "VK did not return a Calls token" }
        val apiUrl = validateApiUrl(tokenData.optString("api_base_url").ifBlank { DEFAULT_OK_API })
        val sessionData = JSONObject()
            .put("auth_token", callToken)
            .put("version", 3)
            .put("device_id", deviceId)
            .put("client_version", "1.0.1")
            .toString()
        val login = postFormWithRetry(
            apiUrl,
            mapOf(
                "session_data" to sessionData,
                "device_id" to deviceId,
                "verification_supported" to "true",
                "verification_supported_v" to "1",
                "client" to "test",
                "gen_token" to "true",
                "method" to "auth.anonymLogin",
                "format" to "JSON",
                "application_key" to OK_APPLICATION_KEY,
            ),
        )
        val sessionKey = login.getString("session_key")
        require(sessionKey.isNotBlank()) { "Calls backend returned an empty session key" }
        val parameters = postFormWithRetry(
            apiUrl,
            mapOf(
                "conversationId" to conversationId,
                "method" to "vchat.getConversationParams",
                "format" to "JSON",
                "application_key" to OK_APPLICATION_KEY,
                "session_key" to sessionKey,
            ),
        )
        checkApiError(parameters)
        val turnServer = parameters.optJSONObject("turn_server")
            ?: parameters.optJSONObject("response")?.optJSONObject("turn_server")
            ?: throw IllegalStateException("Calls backend response has no turn_server object")
        require(turnServer.optString("username").isNotBlank()) {
            "VK Calls returned an empty TURN username"
        }
        require(turnServer.optString("credential").isNotBlank()) {
            "VK Calls returned an empty TURN credential"
        }
        val urls = turnServer.optJSONArray("urls")
            ?: throw IllegalStateException("VK Calls returned no TURN URLs")
        require(urls.length() in 1..16) { "VK Calls returned an invalid TURN URL count" }
        val credentialsJson = JSONObject().put("turn_server", turnServer).toString()
        // This is an auxiliary account session, not the call owner.
        // The source broker leaves these sessions alone; only the owner
        // session performs hangupConversation for the shared conversation.
        return VkCallsSession(
            turnCredentialsJson = credentialsJson,
            apiUrl = apiUrl,
            sessionKey = sessionKey,
            conversationId = conversationId,
            finishAction = {},
        )
    }

    internal fun finishConversation(
        apiUrl: String,
        sessionKey: String,
        conversationId: String,
    ) {
        runCatching {
            postForm(
                apiUrl,
                mapOf(
                    "conversationId" to conversationId,
                    "reason" to "HUNGUP",
                    "method" to "vchat.hangupConversation",
                    "format" to "JSON",
                    "application_key" to OK_APPLICATION_KEY,
                    "session_key" to sessionKey,
                ),
            )
        }
    }

    private fun validateApiUrl(value: String): String {
        val url = URL(value)
        val host = url.host.lowercase()
        val allowedHost = host == "api.ok.ru" || host == "okcdn.ru" || host.endsWith(".okcdn.ru")
        require(
            url.protocol == "https" &&
                allowedHost &&
                (url.port == -1 || url.port == 443) &&
                url.userInfo == null &&
                url.query == null &&
                url.ref == null &&
                url.path in listOf("", "/", "/fb.do")
        ) { "VK Calls returned an unsafe API base URL" }
        return URL(url, "/fb.do").toString()
    }

    private fun postFormWithRetry(endpoint: String, fields: Map<String, String>): JSONObject {
        var lastError: IOException? = null
        repeat(MAX_TRANSIENT_ATTEMPTS) { attempt ->
            try {
                return postForm(endpoint, fields)
            } catch (error: IOException) {
                if (!VkCallsRetryPolicy.isRetryable(error)) throw error
                lastError = error
                if (attempt + 1 < MAX_TRANSIENT_ATTEMPTS) {
                    try {
                        Thread.sleep(VkCallsRetryPolicy.delayMillis(attempt))
                    } catch (interrupted: InterruptedException) {
                        Thread.currentThread().interrupt()
                        throw IOException("VK Calls request retry interrupted", interrupted)
                    }
                }
            }
        }
        throw lastError ?: IOException("VK Calls request failed without a response")
    }

    private fun postForm(endpoint: String, fields: Map<String, String>): JSONObject {
        val url = URL(endpoint)
        require(url.protocol == "https") { "VK Calls API endpoint must use HTTPS" }
        val connection = url.openConnection() as HttpsURLConnection
        try {
            connection.instanceFollowRedirects = false
            connection.requestMethod = "POST"
            connection.connectTimeout = CONNECT_TIMEOUT_MS
            connection.readTimeout = READ_TIMEOUT_MS
            connection.doOutput = true
            connection.useCaches = false
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
            connection.setRequestProperty("Accept", "application/json")
            val body = fields.entries.joinToString("&") { (key, value) ->
                "${encode(key)}=${encode(value)}"
            }
            connection.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }

            val status = connection.responseCode
            val stream = if (status >= 400) connection.errorStream else connection.inputStream
            val bytes = stream?.use { input ->
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(8 * 1024)
                var total = 0
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    total += count
                    require(total <= MAX_RESPONSE_BYTES) { "VK Calls response is too large" }
                    output.write(buffer, 0, count)
                }
                output.toByteArray()
            } ?: ByteArray(0)
            if (status !in 200..299) {
                throw VkCallsHttpException(status)
            }
            val json = JSONObject(String(bytes, Charsets.UTF_8))
            checkApiError(json)
            return json
        } finally {
            connection.disconnect()
        }
    }

    private fun checkApiError(json: JSONObject) {
        val error = json.optJSONObject("error")
        if (error != null) {
            val code = error.optInt("error_code", -1)
            val message = error.optString("error_msg").take(160)
            throw IllegalStateException("VK Calls API error $code: $message")
        }
        val okCode = json.optInt("error_code", 0)
        if (okCode != 0) {
            throw IllegalStateException("VK Calls backend error $okCode")
        }
    }

    private fun encode(value: String): String =
        URLEncoder.encode(value, Charsets.UTF_8.name())

    private const val MAX_TRANSIENT_ATTEMPTS = 3
}

internal class VkCallsHttpException(val statusCode: Int) :
    IOException("VK Calls HTTP request failed with status $statusCode")

internal object VkCallsRetryPolicy {
    fun isRetryable(error: IOException): Boolean =
        error !is VkCallsHttpException ||
            error.statusCode == 408 ||
            error.statusCode == 429 ||
            error.statusCode in 500..599

    fun delayMillis(attemptIndex: Int): Long =
        250L * (attemptIndex.coerceIn(0, 1) + 1)
}
