package com.example.secretlab.face

data class FaceRecognitionResult(
    val label: String,
    val confidence: Float,
    val signedIn: Boolean,
)

data class FaceSessionConfig(
    val backbone: FaceBackboneSpec = FaceBackboneSpec(),
    val inferencePolicy: FaceInferencePolicy = FaceInferencePolicy(),
    val trainingPolicy: FaceTrainingPolicy = FaceTrainingPolicy(),
)

class FaceSession(private val config: FaceSessionConfig = FaceSessionConfig()) {
    private var latestResult: FaceRecognitionResult = FaceRecognitionResult("signed out", 0f, false)
    private var lastTickSeconds: Long = 0L

    fun isReady(): Boolean = config.trainingPolicy.backboneTrainedInColab && config.trainingPolicy.fineTuneOnDevice

    fun tick(nowSeconds: Long): FaceRecognitionResult? {
        if (nowSeconds - lastTickSeconds < config.inferencePolicy.backgroundInferenceEverySeconds) return null
        lastTickSeconds = nowSeconds
        return latestResult
    }

    fun update(result: FaceRecognitionResult) {
        latestResult = result
    }

    fun statusLine(): String = if (latestResult.signedIn) {
        "signed in as ${latestResult.label} (${latestResult.confidence})"
    } else {
        "signed out"
    }
}
