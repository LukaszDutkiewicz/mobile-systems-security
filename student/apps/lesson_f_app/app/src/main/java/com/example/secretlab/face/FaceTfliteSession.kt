package com.example.secretlab.face

import android.content.Context
import org.tensorflow.lite.Interpreter
import org.tensorflow.lite.support.common.FileUtil
import java.nio.ByteBuffer

class FaceTfliteSession(private val context: Context, private val config: FaceSessionConfig = FaceSessionConfig()) {
    private var interpreter: Interpreter? = null
    private val session = FaceSession(config)

    fun open() {
        if (interpreter != null) return
        val model = FileUtil.loadMappedFile(context, config.backbone.modelName + ".tflite")
        interpreter = Interpreter(model, Interpreter.Options().apply { setNumThreads(2) })
    }

    fun close() {
        interpreter?.close()
        interpreter = null
    }

    fun isReady(): Boolean = interpreter != null && session.isReady()

    fun processFrame(frame: ByteBuffer, nowSeconds: Long): FaceRecognitionResult? {
        val interp = interpreter ?: return null
        if (session.tick(nowSeconds) == null) return null
        val output = Array(1) { FloatArray(config.backbone.embeddingSize) }
        interp.run(frame, output)
        val confidence = output[0].maxOrNull() ?: 0f
        val label = if (confidence > config.inferencePolicy.rejectThreshold) "User 1" else "signed out"
        val signedIn = label != "signed out"
        val result = FaceRecognitionResult(label = label, confidence = confidence, signedIn = signedIn)
        session.update(result)
        return result
    }

    fun statusLine(): String = session.statusLine()
}
