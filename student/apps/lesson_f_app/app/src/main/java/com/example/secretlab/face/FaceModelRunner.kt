package com.example.secretlab.face

data class FaceModelArtifact(
    val spec: FaceBackboneSpec = FaceBackboneSpec(),
    val pathOnDevice: String = "app/src/main/assets/tiny_face_backbone.tflite",
    val labelsPath: String = "app/src/main/assets/tiny_face_labels.txt",
)

data class FacePreprocessingPipeline(
    val targetWidth: Int = FaceBackboneSpec().inputWidth,
    val targetHeight: Int = FaceBackboneSpec().inputHeight,
    val normalizeToUnitRange: Boolean = true,
)

data class FaceInferencePolicy(
    val rejectThreshold: Float = 0.72f,
    val backgroundInferenceEverySeconds: Int = 2,
)

data class FaceFineTuningBridge(
    val artifact: FaceModelArtifact = FaceModelArtifact(),
    val preprocessing: FacePreprocessingPipeline = FacePreprocessingPipeline(),
    val policy: FaceInferencePolicy = FaceInferencePolicy(),
) {
    val isReadyForOnDeviceTraining: Boolean
        get() = artifact.spec == preprocessing.toSpec() && artifact.pathOnDevice.isNotBlank()

    val isReadyForInference: Boolean
        get() = isReadyForOnDeviceTraining && artifact.labelsPath.isNotBlank() && policy.rejectThreshold in 0.0f..1.0f

    val sessionSummary: String
        get() = "${artifact.spec.modelName}:${artifact.spec.inputShape}/${artifact.spec.embeddingSize}d"
}

data class FaceTrainingProgress(
    val epoch: Int = 0,
    val totalEpochs: Int = 0,
    val loss: Double? = null,
    val accuracy: Double? = null,
) {
    val hasMetrics: Boolean
        get() = loss != null && accuracy != null

    fun progressFraction(): Float =
        if (totalEpochs <= 0) 0f else epoch.coerceAtMost(totalEpochs).toFloat() / totalEpochs.toFloat()

    fun summary(): String = when {
        totalEpochs <= 0 -> "training not started"
        hasMetrics -> "epoch $epoch/$totalEpochs, loss=${"%.2f".format(loss)}, acc=${"%.2f".format(accuracy)}"
        else -> "epoch $epoch/$totalEpochs, metrics pending"
    }
}

private fun FacePreprocessingPipeline.toSpec(): FaceBackboneSpec = FaceBackboneSpec(
    inputWidth = targetWidth,
    inputHeight = targetHeight,
    inputChannels = 3,
)
