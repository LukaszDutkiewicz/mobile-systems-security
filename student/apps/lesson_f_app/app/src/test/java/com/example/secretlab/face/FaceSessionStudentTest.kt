package com.example.secretlab.face

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FaceSessionStudentTest {
    @Test fun sessionStartsSignedOut() {
        val session = FaceSession()
        assertFalse(session.isReady())
        assertEquals("signed out", session.statusLine())
    }

    @Test fun sessionReportsSignedInResult() {
        val session = FaceSession(FaceSessionConfig(trainingPolicy = FaceTrainingPolicy(backboneTrainedInColab = true)))
        session.update(FaceRecognitionResult("User 1", 0.91f, true))
        assertTrue(session.isReady())
        assertTrue(session.statusLine().startsWith("signed in as User 1"))
    }
}
