package com.example.secretlab.face

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class FaceTrainingPolicyStudentTest {
    @Test fun defaultPolicyExpectsOnDeviceFineTuning() {
        val policy = FaceTrainingPolicy()
        assertTrue(policy.fineTuneOnDevice)
        assertEquals(2, policy.backgroundInferenceEverySeconds)
    }

    @Test fun colabBackboneCanBeMarkedReady() {
        val policy = FaceTrainingPolicy(backboneTrainedInColab = true)
        assertTrue(policy.backboneTrainedInColab)
    }
}
