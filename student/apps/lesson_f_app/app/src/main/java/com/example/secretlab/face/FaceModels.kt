package com.example.secretlab.face

import android.net.Uri

data class FacePhoto(
    val uri: Uri,
    val label: String,
)

data class FaceSlot(
    val userId: String,
    val displayName: String,
    val photos: MutableList<FacePhoto> = mutableListOf(),
) {
    val isReady: Boolean get() = photos.size >= 10
}

enum class InputSource { CAMERA, GALLERY }

data class FaceTrainingState(
    val backboneReady: Boolean = false,
    val headFineTuned: Boolean = false,
    val lastRunAtEpochSeconds: Long? = null,
)
