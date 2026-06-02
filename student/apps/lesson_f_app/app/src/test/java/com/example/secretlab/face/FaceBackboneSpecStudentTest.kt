package com.example.secretlab.face

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class FaceBackboneSpecStudentTest {
    @Test fun tinyBackboneUsesFixedInputShape() {
        val spec = FaceBackboneSpec()
        assertEquals(96, spec.inputWidth)
        assertEquals(96, spec.inputHeight)
        assertEquals(3, spec.inputChannels)
        assertEquals(32, spec.embeddingSize)
        assertEquals("96x96x3", spec.inputShape)
    }

    @Test fun fineTuningPlanTargetsTheHeadOnly() {
        val plan = FaceFineTuningPlan()
        assertTrue(plan.trainableLayers.contains("head"))
        assertEquals(2, plan.backgroundInferenceEverySeconds)
    }
}
