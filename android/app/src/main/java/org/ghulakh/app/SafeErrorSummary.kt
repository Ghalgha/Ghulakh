package org.ghulakh.app

import java.io.IOException
import java.net.SocketTimeoutException
import java.net.UnknownHostException

/**
 * Produces diagnostics without exposing exception messages, causes, request bodies,
 * credentials, tokens, or server-controlled response text.
 */
internal fun safeErrorSummary(error: Throwable): String = when (error) {
    is VkCallsHttpException -> "VK Calls HTTP request failed (status ${error.statusCode})"
    is CredentialStoreException.KeyUnavailable -> "Android Keystore key is unavailable"
    is CredentialStoreException.Corrupted -> "Stored connection profile is corrupted"
    is CredentialStoreException.PersistenceFailure -> "Connection profile persistence failed"
    is SocketTimeoutException -> "Network operation timed out"
    is UnknownHostException -> "Network host lookup failed"
    is IOException -> "Network I/O operation failed"
    is InterruptedException -> "Operation was interrupted"
    else -> "Operation failed (${error.javaClass.simpleName.take(64)})"
}
