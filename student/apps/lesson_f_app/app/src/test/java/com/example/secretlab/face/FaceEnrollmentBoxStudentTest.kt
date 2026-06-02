package com.example.secretlab.face

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FaceEnrollmentBoxStudentTest {
    @Test fun hasFiveSlots() {
        val box = FaceEnrollmentBox()
        assertEquals(5, box.slots.size)
    }

    @Test fun allReadyRequiresTenPhotosEach() {
        val box = FaceEnrollmentBox()
        assertFalse(box.allReady())
        box.slots.forEach { slot -> repeat(10) { slot.photos.add(FacePhoto(android.net.Uri.EMPTY, "x")) } }
        assertTrue(box.allReady())
    }
}
