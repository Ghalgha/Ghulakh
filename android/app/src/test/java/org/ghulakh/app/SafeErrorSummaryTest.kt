package org.ghulakh.app

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class SafeErrorSummaryTest {
    @Test
    fun arbitraryExceptionMessageAndCauseAreNeverExposed() {
        val secret = "access_token=vk-secret password=turn-secret"
        val error = IllegalStateException(secret, IllegalArgumentException("credential=hidden"))

        val summary = safeErrorSummary(error)

        assertEquals("Операция завершилась ошибкой (IllegalStateException)", summary)
        listOf("vk-secret", "turn-secret", "hidden", "access_token", "password").forEach {
            assertFalse(summary.contains(it))
        }
    }

    @Test
    fun knownNetworkAndCredentialErrorsExposeOnlySafeCategories() {
        assertEquals("Ошибка запроса VK Calls (HTTP 503)", safeErrorSummary(VkCallsHttpException(503)))
        assertEquals(
            "Ключ Android Keystore недоступен",
            safeErrorSummary(CredentialStoreException.KeyUnavailable(IllegalStateException("secret=hidden"))),
        )
        assertEquals("Сетевой запрос превысил время ожидания", safeErrorSummary(java.net.SocketTimeoutException("token=hidden")))
    }

    @Test
    fun vkCallsApiErrorDoesNotEchoUntrustedServerMessage() {
        val error = runCatching {
            VkCallsCredentialProvider.checkApiError(
                JSONObject("""{"error":{"error_code":5,"error_msg":"access_token=vk-secret credential=turn-secret"}}"""),
            )
        }.exceptionOrNull()

        val summary = safeErrorSummary(requireNotNull(error))
        assertEquals("Operation failed (IllegalStateException)", summary)
        assertFalse(error.message.orEmpty().contains("vk-secret"))
        assertFalse(error.message.orEmpty().contains("turn-secret"))
    }
}
