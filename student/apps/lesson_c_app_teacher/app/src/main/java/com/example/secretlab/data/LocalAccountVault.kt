package com.example.secretlab.data

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

class LocalAccountVault(context: Context) {
    private val encryptedBox = EncryptedSharedPreferences.create(
        context,
        BIN_NAME,
        MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    fun saveLocalAccount(mail: String, secret: String) {
        encryptedBox.edit()
            .putString(MAIL_SLOT, mail)
            .putString(SECRET_SLOT, secret)
            .apply()
    }

    fun readAccountMail(): String? {
        return encryptedBox.getString(MAIL_SLOT, null)
    }

    fun readAccountSecret(): String? {
        return encryptedBox.getString(SECRET_SLOT, null)
    }

    companion object {
        const val BIN_NAME = "account_memory"
        const val MAIL_SLOT = "owner_mail"
        const val SECRET_SLOT = "owner_secret"
    }
}
