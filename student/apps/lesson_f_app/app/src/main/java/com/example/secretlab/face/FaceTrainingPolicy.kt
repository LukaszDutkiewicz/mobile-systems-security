package com.example.secretlab.face

data class FaceTrainingPolicy(
    val backboneTrainedInColab: Boolean = false,
    val fineTuneOnDevice: Boolean = true,
    val backgroundInferenceEverySeconds: Int = 2,
    val backboneSpec: FaceBackboneSpec = FaceBackboneSpec(),
)
