package com.example.secretlab.secure

import com.example.secretlab.BuildConfig

object AppSecrets {
    init {
        System.loadLibrary("secret_keys")
    }

    private external fun decryptBlob(encodedBlob: String): String

    fun readMapApiKey(): String? =
        BuildConfig.MAP_API_KEY_B64.takeIf { it.isNotBlank() }?.let(::decryptBlob)

    fun readTask4Secret(): String? =
        BuildConfig.TASK4_SECRET_B64.takeIf { it.isNotBlank() }?.let(::decryptBlob)
}
