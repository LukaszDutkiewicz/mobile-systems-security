package com.example.secretlab.face

object FaceCompletionCodeBook {
    fun trainingMseCode(mse: Double): String = when {
        mse <= 0.10 -> "1042"
        mse <= 0.20 -> "2042"
        mse <= 0.30 -> "3042"
        else -> "9042"
    }

    fun trainingAccuracyCode(accuracy: Double): String = when {
        accuracy >= 0.95 -> "9517"
        accuracy >= 0.90 -> "9017"
        accuracy >= 0.80 -> "8017"
        else -> "1017"
    }

    fun signedInCode(session: FaceSession): String = if (session.statusLine().startsWith("signed in as ")) "7421" else "0000"

    fun runnerReadyCode(bridge: FaceFineTuningBridge): String = if (bridge.isReadyForInference) "6184" else "0000"

    fun testsPassCode(box: FaceEnrollmentBox): String = if (box.allReady()) "9036" else "0000"
}
