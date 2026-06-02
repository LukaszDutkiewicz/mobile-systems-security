package com.example.secretlab.face

import org.junit.Assert.assertTrue
import org.junit.Test

class FaceModelRunnerStudentTest {
    @Test fun runnerBridgeMatchesBackboneShape() {
        val bridge = FaceFineTuningBridge()
        assertTrue(bridge.isReadyForOnDeviceTraining)
        assertTrue(bridge.isReadyForInference)
        assertTrue(bridge.sessionSummary.contains("tiny_face_backbone"))
    }
}
