package com.example.secretlab.debug

import java.security.MessageDigest

object LocalHashDemo {
    // TODO(C04-HASH): use this helper to inspect the local hash demo.
    fun sha256(input: String): String {
        val bytes = MessageDigest.getInstance("SHA-256").digest(input.toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }
    }

    // TODO(C07-SALT): include the salt in the hash input.
    // Starter bug: the current version ignores the salt completely.
    fun saltedSha256(input: String, salt: String): String {
        return sha256("$salt:$input")
    }

    // TODO(C04-SESSION): show that a local hash alone is not enough to recover a usable session.
    fun localHashCanRestoreSession(hashedSecret: String): Boolean {
        return false
    }

    fun sameSecretDifferentSaltMatch(input: String, saltA: String, saltB: String): Boolean {
        return saltedSha256(input, saltA) == saltedSha256(input, saltB)
    }
}
