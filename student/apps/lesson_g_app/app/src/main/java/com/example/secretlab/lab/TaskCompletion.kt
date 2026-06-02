package com.example.secretlab.lab

data class ApiKeyState(val storedApiKey: String?, val canUseSecureStorage: Boolean)

data class IntegrityState(
    val verdict: String?,
    val appPackageNameMatches: Boolean,
    val requestIsBoundToAppIdentity: Boolean,
)

object TaskCompletion {
    const val TASK2_CODE = "K2Q7M"
    const val TASK3_CODE = "I3B9T"

    fun task2Code(state: ApiKeyState): String? {
        // TODO(L06-2): reveal the short code only after the secure-storage/API-key flow is ready.
        return null
    }

    fun task3Code(state: IntegrityState): String? {
        // TODO(L06-3): reveal the short code only after the integrity-gated backend request is ready.
        return null
    }
}
