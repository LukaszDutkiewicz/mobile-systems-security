package com.example.secretlab.secure

import android.content.Context

object AppSecretsStore {
    private const val MAP_API_KEY_PREF = "map_api_key"
    private const val TASK_4_SECRET_KEY = "task4_secret_5char"
    private const val TASK_4_SECRET_VALUE = "Q7X2R"

    fun open(context: Context) = SecurePrefs.open(context).also { prefs ->
        if (prefs.getString(TASK_4_SECRET_KEY, null) == null) {
            prefs.edit().putString(TASK_4_SECRET_KEY, TASK_4_SECRET_VALUE).apply()
        }
    }

    fun readMapApiKey(context: Context): String? =
        SecurePrefs.open(context).getString(MAP_API_KEY_PREF, null)

    fun readTask4Secret(context: Context): String? =
        SecurePrefs.open(context).getString(TASK_4_SECRET_KEY, null)
}
