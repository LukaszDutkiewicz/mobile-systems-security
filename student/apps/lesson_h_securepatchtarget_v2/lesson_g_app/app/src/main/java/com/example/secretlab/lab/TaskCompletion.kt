package com.example.secretlab.lab

data class ProvenanceState(
    val signingIdentityMatchesExpected: Boolean,
    val buildLooksTampered: Boolean,
    val installTimeTrustIsSeparatedFromRuntimeTrust: Boolean,
)

data class IntegrityState(
    val verdict: String?,
    val appPackageNameMatches: Boolean,
    val requestIsBoundToAppIdentity: Boolean,
)

object TaskCompletion {
    fun task2Check(state: ProvenanceState): Boolean {
        // TODO(G02): implement the APK / bundle provenance check from the lab proposal.
        return false
    }

    fun task3Check(state: IntegrityState): Boolean {
        // TODO(G03): implement the integrity-gated backend request from the lab proposal.
        return false
    }
}
