package com.example.secretlab.face

class FaceEnrollmentBox {
    val slots: List<FaceSlot> = listOf(
        FaceSlot("u1", "User 1"),
        FaceSlot("u2", "User 2"),
        FaceSlot("u3", "User 3"),
        FaceSlot("u4", "User 4"),
        FaceSlot("u5", "User 5"),
    )

    fun slot(index: Int): FaceSlot = slots[index]
    fun replacePhotos(userIndex: Int, photos: List<FacePhoto>) {
        val slot = slots[userIndex]
        slot.photos.clear()
        slot.photos.addAll(photos.take(20))
    }
    fun addPhoto(userIndex: Int, photo: FacePhoto) { slots[userIndex].photos.add(photo) }
    fun removePhoto(userIndex: Int, photo: FacePhoto) { slots[userIndex].photos.remove(photo) }
    fun allReady(): Boolean = slots.all { it.isReady }
}
