package org.ghulakh.app

import java.io.IOException
import java.net.SocketTimeoutException
import java.net.UnknownHostException

/**
 * Produces diagnostics without exposing exception messages, causes, request bodies,
 * credentials, tokens, or server-controlled response text.
 */
internal fun safeErrorSummary(error: Throwable): String = when (error) {
    is VkCallsHttpException -> "Ошибка запроса VK Calls (HTTP ${error.statusCode})"
    is CredentialStoreException.KeyUnavailable -> "Ключ Android Keystore недоступен"
    is CredentialStoreException.Corrupted -> "Сохранённый профиль повреждён"
    is CredentialStoreException.PersistenceFailure -> "Не удалось сохранить профиль"
    is SocketTimeoutException -> "Сетевой запрос превысил время ожидания"
    is UnknownHostException -> "Не удалось определить адрес сервера"
    is IOException -> "Ошибка сетевого обмена"
    is InterruptedException -> "Операция прервана"
    else -> "Операция завершилась ошибкой (${error.javaClass.simpleName.take(64)})"
}
