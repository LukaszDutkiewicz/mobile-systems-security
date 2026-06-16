package com.example.secretlab.insecure

import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import java.security.SecureRandom

object CryptoHelper {
    fun encryptLegacy(value: String): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val key = generateSessionKey()
        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val gcmSpec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec)
        val ciphertext = cipher.doFinal(value.toByteArray())
        return iv + ciphertext
    }

    fun generateSessionKey(): ByteArray {
        val generator = KeyGenerator.getInstance("AES")
        generator.init(128)
        return generator.generateKey().encoded
    }
}
