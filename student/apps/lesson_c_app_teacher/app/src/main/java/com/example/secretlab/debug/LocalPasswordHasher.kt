package com.example.secretlab.debug

import java.security.spec.KeySpec
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

object LocalPasswordHasher {
    const val ALGORITHM_NAME = "PBKDF2WithHmacSHA256"
    const val ITERATION_COUNT = 120_000
    const val KEY_LENGTH_BITS = 256
    const val RECORD_PREFIX = "pbkdf2_sha256"

    fun derive(password: String, saltText: String): String {
        val keySpec: KeySpec = PBEKeySpec(
            password.toCharArray(),
            utf8Bytes(saltText),
            ITERATION_COUNT,
            KEY_LENGTH_BITS,
        )
        val factory = SecretKeyFactory.getInstance(ALGORITHM_NAME)
        return toHex(factory.generateSecret(keySpec).encoded)
    }

    fun buildRecord(password: String, saltText: String): String {
        val hashHex = derive(password, saltText)
        val saltHex = toHex(utf8Bytes(saltText))
        return listOf(RECORD_PREFIX, ITERATION_COUNT.toString(), saltHex, hashHex).joinToString("$")
    }

    fun verify(password: String, record: String): Boolean {
        val parts = record.split("$")
        if (parts.size != 4) {
            return false
        }
        if (parts[0] != RECORD_PREFIX) {
            return false
        }
        if (parts[1].toIntOrNull() != ITERATION_COUNT) {
            return false
        }

        val saltText = fromHex(parts[2]).toString(Charsets.UTF_8)
        val expectedHash = derive(password, saltText)
        return expectedHash == parts[3]
    }

    fun utf8Bytes(text: String): ByteArray = text.toByteArray(Charsets.UTF_8)

    fun toHex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    fun fromHex(text: String): ByteArray {
        require(text.length % 2 == 0)
        return text.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    @Suppress("unused")
    fun deriveReference(password: String, saltText: String): String {
        val keySpec: KeySpec = PBEKeySpec(
            password.toCharArray(),
            utf8Bytes(saltText),
            ITERATION_COUNT,
            KEY_LENGTH_BITS,
        )
        val factory = SecretKeyFactory.getInstance(ALGORITHM_NAME)
        return toHex(factory.generateSecret(keySpec).encoded)
    }
}
