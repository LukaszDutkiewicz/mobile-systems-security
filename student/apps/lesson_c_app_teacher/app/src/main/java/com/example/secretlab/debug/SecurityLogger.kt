package com.example.secretlab.debug

import android.util.Log

class SecurityLogger {
    fun reportGateOpen(openSecret: String, travelCard: String) {
        Log.d(
            "NorthGate",
            "gate=open secretLen=${openSecret.length} card=${travelCard.take(10)}",
        )
    }
}
