package com.example.secretlab.insecure

import android.content.Context

class SecretStore(context: Context) {
    @Suppress("UNUSED_PARAMETER")
    private val appContext = context.applicationContext
    private var sessionToken: String? = null

    fun demoApiKey(): String = ""

    fun saveSessionToken(token: String) {
        sessionToken = token
    }

    fun loadSessionToken(): String? = sessionToken
}
