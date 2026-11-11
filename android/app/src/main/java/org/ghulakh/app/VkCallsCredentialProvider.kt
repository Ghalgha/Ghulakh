package org.ghulakh.app

import org.json.JSONObject
import java.io.ByteArrayOutputStream
import javax.net.ssl.HttpsURLConnection
import java.net.URL
import java.net.URLEncoder
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

data class VkCallsSession(
    val turnCredentialsJson: String,
    private val apiUrl: String,
    private val sessionKey: String,
    private val conversationId: String,
) {
    private val finished = AtomicBoolean(false)

    fun finish() {
        finishOnce {
            VkCallsCredentialProvider.finishConversation(
                apiUrl,
                sessionKey,
                conversationId,
            )
        }
    }

    internal fun finishOnce(action: () -> Unit) {
        if (finished.compareAndSet(false, true)) action()
    }
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

    fun obtain(accessToken: String): VkCallsSession {
        require(accessToken.isNotBlank()) { "VK access token is empty" }
        require(accessToken.length <= 16_384) { "VK access token is too long" }

        val deviceId = UUID.randomUUID().toString()
        val tokenResponse = postForm(
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
        val login = postForm(
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

            val parameters = postForm(
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
            require(status in 200..299) { "VK Calls HTTP request failed with status $status" }
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
}
