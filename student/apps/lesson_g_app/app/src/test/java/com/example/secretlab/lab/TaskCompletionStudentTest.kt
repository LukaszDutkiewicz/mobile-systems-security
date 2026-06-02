package com.example.secretlab.lab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class TaskCompletionStudentTest {
    @Test
    fun task2CodeAppearsOnlyWhenSecureStorageAndApiKeyAreReady() {
        assertNull(TaskCompletion.task2Code(ApiKeyState(storedApiKey = null, canUseSecureStorage = true)))
        assertNull(TaskCompletion.task2Code(ApiKeyState(storedApiKey = "abc", canUseSecureStorage = false)))
        assertEquals(
            TaskCompletion.TASK2_CODE,
            TaskCompletion.task2Code(ApiKeyState(storedApiKey = "api-key-present", canUseSecureStorage = true)),
        )
    }

    @Test
    fun task3CodeAppearsOnlyWhenIntegrityVerdictAndBindingAreReady() {
        assertNull(
            TaskCompletion.task3Code(
                IntegrityState(
                    verdict = null,
                    appPackageNameMatches = true,
                    requestIsBoundToAppIdentity = true,
                ),
            ),
        )
        assertNull(
            TaskCompletion.task3Code(
                IntegrityState(
                    verdict = "ALLOW",
                    appPackageNameMatches = false,
                    requestIsBoundToAppIdentity = true,
                ),
            ),
        )
        assertNull(
            TaskCompletion.task3Code(
                IntegrityState(
                    verdict = "ALLOW",
                    appPackageNameMatches = true,
                    requestIsBoundToAppIdentity = false,
                ),
            ),
        )
        assertEquals(
            TaskCompletion.TASK3_CODE,
            TaskCompletion.task3Code(
                IntegrityState(
                    verdict = "ALLOW",
                    appPackageNameMatches = true,
                    requestIsBoundToAppIdentity = true,
                ),
            ),
        )
    }
}
