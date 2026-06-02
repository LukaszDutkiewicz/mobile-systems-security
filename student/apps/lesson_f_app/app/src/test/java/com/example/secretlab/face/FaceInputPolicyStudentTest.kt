package com.example.secretlab.face

import org.junit.Assert.assertEquals
import org.junit.Test

class FaceInputPolicyStudentTest {
    @Test fun cameraIsPrimaryAndGalleryIsFallback() {
        val policy = FaceInputPolicy(InputSource.CAMERA)
        assertEquals(InputSource.CAMERA, policy.preferredSource)
        assertEquals(InputSource.GALLERY, policy.fallbackSource)
    }

    @Test fun galleryCanBePrimaryToo() {
        val policy = FaceInputPolicy(InputSource.GALLERY)
        assertEquals(InputSource.GALLERY, policy.preferredSource)
        assertEquals(InputSource.CAMERA, policy.fallbackSource)
    }
}
