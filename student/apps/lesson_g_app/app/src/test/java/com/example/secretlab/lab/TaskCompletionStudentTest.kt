package com.example.secretlab.lab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TaskCompletionStudentTest {
    @Test
    fun task2CodeAppearsOnlyWhenProvenanceChecksPass() {
        assertFalse(
            TaskCompletion.task2Check(
                ProvenanceState(
                    signingIdentityMatchesExpected = false,
                    buildLooksTampered = false,
                    installTimeTrustIsSeparatedFromRuntimeTrust = true,
                ),
            ),
        )
        assertFalse(
            TaskCompletion.task2Check(
                ProvenanceState(
                    signingIdentityMatchesExpected = true,
                    buildLooksTampered = true,
                    installTimeTrustIsSeparatedFromRuntimeTrust = true,
                ),
            ),
        )
        assertFalse(
            TaskCompletion.task2Check(
                ProvenanceState(
                    signingIdentityMatchesExpected = true,
                    buildLooksTampered = false,
                    installTimeTrustIsSeparatedFromRuntimeTrust = false,
                ),
            ),
        )
        assertTrue(
            TaskCompletion.task2Check(
                ProvenanceState(
                    signingIdentityMatchesExpected = true,
                    buildLooksTampered = false,
                    installTimeTrustIsSeparatedFromRuntimeTrust = true,
                ),
            ),
        )
    }

    @Test
    fun task3CodeAppearsOnlyWhenIntegrityVerdictAndBindingAreReady() {
        assertFalse(
            TaskCompletion.task3Check(
                IntegrityState(
                    verdict = null,
                    appPackageNameMatches = true,
                    requestIsBoundToAppIdentity = true,
                ),
            ),
        )
        assertFalse(
            TaskCompletion.task3Check(
                IntegrityState(
                    verdict = "ALLOW",
                    appPackageNameMatches = false,
                    requestIsBoundToAppIdentity = true,
                ),
            ),
        )
        assertFalse(
            TaskCompletion.task3Check(
                IntegrityState(
                    verdict = "ALLOW",
                    appPackageNameMatches = true,
                    requestIsBoundToAppIdentity = false,
                ),
            ),
        )
        assertTrue(
            TaskCompletion.task3Check(
                IntegrityState(
                    verdict = "ALLOW",
                    appPackageNameMatches = true,
                    requestIsBoundToAppIdentity = true,
                ),
            ),
        )
    }
}
