package org.ghulakh.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class WipingBufferTest {
    private class InspectableProfileBuffer : WipingByteArrayOutputStream() {
        fun backingBuffer(): ByteArray = buf
    }

    private class InspectableVkResponseBuffer : VkCallsWipingByteArrayOutputStream() {
        fun backingBuffer(): ByteArray = buf
    }

    private class InspectableFingerprintBuffer : FingerprintWipingByteArrayOutputStream() {
        fun backingBuffer(): ByteArray = buf
    }

    @Test
    fun profileSerializationBufferIsWipedAndReset() {
        assertBufferIsWiped(InspectableProfileBuffer(), byteArrayOf(1, 2, 3, 4)) { it.wipe() }
    }

    @Test
    fun vkCallsHttpResponseBufferIsWipedAndReset() {
        assertBufferIsWiped(InspectableVkResponseBuffer(), byteArrayOf(5, 6, 7, 8)) { it.wipe() }
    }

    @Test
    fun credentialFingerprintCanonicalBufferIsWipedAndReset() {
        assertBufferIsWiped(InspectableFingerprintBuffer(), byteArrayOf(9, 10, 11, 12)) { it.wipe() }
    }

    private fun <T> assertBufferIsWiped(
        stream: T,
        secret: ByteArray,
        wipe: (T) -> Unit,
    ) where T : java.io.ByteArrayOutputStream {
        stream.write(secret)
        val backing = when (stream) {
            is InspectableProfileBuffer -> stream.backingBuffer()
            is InspectableVkResponseBuffer -> stream.backingBuffer()
            is InspectableFingerprintBuffer -> stream.backingBuffer()
            else -> error("unsupported test buffer")
        }
        assertTrue(backing.any { it != 0.toByte() })
        wipe(stream)
        assertTrue(backing.all { it == 0.toByte() })
        assertEquals(0, stream.size())
        assertFalse(stream.toByteArray().isNotEmpty())
    }
}
