package com.example.secretlab.secure

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.security.SecureRandom

class SecretBoxStudentTest {
    private val random = SecureRandom()

    @Test
    fun encryptsAsIvPlusCiphertextAndDecryptsBack() {
        val keyProvider = InMemoryKeyProvider(random)
        val box = SecretBox(keyProvider)

        val plaintext = "otpauth://totp/demo?secret=ABC".encodeToByteArray()
        val iv = ByteArray(SecretBox.IV_BYTES).also(random::nextBytes)

        val message = box.encrypt(plaintext, iv)

        assertEquals(SecretBox.IV_BYTES, iv.size)
        assertEquals(true, message.size > iv.size)
        assertArrayEquals(iv, message.copyOfRange(0, SecretBox.IV_BYTES))

        val decrypted = box.decrypt(message)
        assertArrayEquals(plaintext, decrypted)
    }

    @Test
    fun returnsNullWhenMessageTooShort() {
        val box = SecretBox(InMemoryKeyProvider(random))
        val decrypted = box.decrypt(ByteArray(SecretBox.IV_BYTES - 1))
        assertNull(decrypted)
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsWrongIvLengthInEncrypt() {
        val box = SecretBox(InMemoryKeyProvider(random))
        val plaintext = "secret".encodeToByteArray()
        val ivWrong = ByteArray(SecretBox.IV_BYTES - 1).also(random::nextBytes)
        box.encrypt(plaintext, ivWrong)
    }

    @Test
    fun detectsTamperingAndReturnsNull() {
        val keyProvider = InMemoryKeyProvider(random)
        val box = SecretBox(keyProvider)

        val plaintext = "secret".encodeToByteArray()
        val iv = ByteArray(SecretBox.IV_BYTES).also(random::nextBytes)
        val message = box.encrypt(plaintext, iv).clone()

        message[message.lastIndex] = (message[message.lastIndex].toInt() xor 0x01).toByte()

        val decrypted = box.decrypt(message)
        assertNull(decrypted)
    }

    @Test
    fun bindsCiphertextToContextWithAad() {
        val keyProvider = InMemoryKeyProvider(random)
        val box = SecretBox(keyProvider)

        val plaintext = "seed".encodeToByteArray()
        val iv = ByteArray(SecretBox.IV_BYTES).also(random::nextBytes)
        val ctxGood = "mfa:totp_seed:v1".encodeToByteArray()
        val ctxBad = "mfa:totp_seed:v2".encodeToByteArray()

        val message = box.encryptBound(plaintext, iv, ctxGood)
        assertArrayEquals(plaintext, box.decryptBound(message, ctxGood))
        assertNull(box.decryptBound(message, ctxBad))
    }
}
