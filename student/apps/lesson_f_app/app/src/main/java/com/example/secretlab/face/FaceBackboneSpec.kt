package com.example.secretlab.face

data class FaceBackboneSpec(
    val modelName: String = "tiny_face_backbone",
    val inputWidth: Int = 96,
    val inputHeight: Int = 96,
    val inputChannels: Int = 3,
    val embeddingSize: Int = 32,
    val colabExportFormat: String = "tflite",
    val onDeviceFineTuneLayers: List<String> = listOf("head"),
) {
    val inputShape: String = "${inputHeight}x${inputWidth}x${inputChannels}"
}

data class FaceBackboneCheckpoint(
    val spec: FaceBackboneSpec = FaceBackboneSpec(),
    val exportedFromColab: Boolean = false,
    val localArtifactPath: String = "app/src/main/assets/tiny_face_backbone.tflite",
)

data class FaceFineTuningPlan(
    val backbone: FaceBackboneSpec = FaceBackboneSpec(),
    val trainingSource: String = "enrolled user crops",
    val trainableLayers: List<String> = listOf("head"),
    val backgroundInferenceEverySeconds: Int = 2,
)
