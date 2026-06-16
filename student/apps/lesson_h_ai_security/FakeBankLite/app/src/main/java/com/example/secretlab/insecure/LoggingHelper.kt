package com.example.secretlab.insecure

import android.util.Log

object LoggingHelper {
    fun dumpSensitiveState(token: String, noteTitle: String) {
        Log.d("InsecureNotes", "token=$token note=$noteTitle")
    }
}
