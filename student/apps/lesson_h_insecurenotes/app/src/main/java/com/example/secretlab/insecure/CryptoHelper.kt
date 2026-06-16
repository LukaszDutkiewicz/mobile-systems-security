package com.example.secretlab.insecure

import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

object CryptoHelper {
    fun encryptLegacy(value: String): ByteArray {
        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        val key = SecretKeySpec("0123456789abcdef".toByteArray(), "AES")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return cipher.doFinal(value.toByteArray())
    }
}
