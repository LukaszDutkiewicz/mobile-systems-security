package com.example.secretlab.insecure

import android.content.Context

class SecretStore(context: Context) {
    private val prefs = context.getSharedPreferences("insecure_notes", Context.MODE_PRIVATE)

    fun demoApiKey(): String = "demo-api-key-1A2B3C"

    fun saveSessionToken(token: String) {
        prefs.edit().putString("session_token", token).apply()
    }

    fun loadSessionToken(): String? = prefs.getString("session_token", null)
}
