package com.example.secretlab.debug

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SecurityExercisesTeacherTest {
    @Test
    fun localHashDoesNotRestoreSession() {
        val digest = LocalHashDemo.sha256("student123!")
        assertFalse(LocalHashDemo.localHashCanRestoreSession(digest))
    }

    @Test
    fun saltedHashesDifferForDifferentSalts() {
        assertFalse(LocalHashDemo.sameSecretDifferentSaltMatch("vault-c05-01!", "mint-01", "mint-02"))
    }

    @Test
    fun pbkdf2DeriveMatchesReference() {
        assertEquals(
            LocalPasswordHasher.deriveReference("vault-c05-01!", "mint-01"),
            LocalPasswordHasher.derive("vault-c05-01!", "mint-01"),
        )
    }

    @Test
    fun pbkdf2RecordVerifiesGoodAndRejectsBadPassword() {
        val record = LocalPasswordHasher.buildRecord("vault-c05-01!", "mint-01")
        assertTrue(record.startsWith("pbkdf2_sha256$120000$"))
        assertTrue(LocalPasswordHasher.verify("vault-c05-01!", record))
        assertFalse(LocalPasswordHasher.verify("wrong-pass", record))
    }
}
