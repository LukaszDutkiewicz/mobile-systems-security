package com.example.secretlab.face

import org.junit.Assert.assertEquals
import org.junit.Test

class FaceCompletionCodeBookStudentTest {
    @Test fun codesFollowCompletionSignals() {
        assertEquals("1042", FaceCompletionCodeBook.trainingMseCode(0.10))
        assertEquals("9017", FaceCompletionCodeBook.trainingAccuracyCode(0.91))

        val session = FaceSession().apply { update(FaceRecognitionResult("User 1", 0.99f, true)) }
        assertEquals("7421", FaceCompletionCodeBook.signedInCode(session))

        val bridge = FaceFineTuningBridge()
        assertEquals("6184", FaceCompletionCodeBook.runnerReadyCode(bridge))

        val box = FaceEnrollmentBox().apply {
            slots.forEach { slot -> repeat(10) { slot.photos.add(FacePhoto(android.net.Uri.EMPTY, "x")) } }
        }
        assertEquals("9036", FaceCompletionCodeBook.testsPassCode(box))
    }
}
