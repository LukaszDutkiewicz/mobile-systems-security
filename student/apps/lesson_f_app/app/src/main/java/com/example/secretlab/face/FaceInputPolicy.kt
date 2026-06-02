package com.example.secretlab.face

data class FaceInputPolicy(
    val preferredSource: InputSource = InputSource.CAMERA,
) {
    val fallbackSource: InputSource
        get() = if (preferredSource == InputSource.CAMERA) InputSource.GALLERY else InputSource.CAMERA
}
