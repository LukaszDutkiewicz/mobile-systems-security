# Lesson F App

Starter app for the face biometrics lab.

What the lab should exercise:
- 5 fixed enrollment rows
- per-user photo editing
- camera-first capture with gallery fallback
- on-device fine-tuning after Colab backbone prep
- continuous background inference after training
- tiny CNN backbone with `96x96x3` input and `32d` embedding
- Android runner bridge that checks inference and fine-tuning readiness

Main files:
- `app/src/main/java/com/example/secretlab/MainActivity.kt`
- `app/src/main/java/com/example/secretlab/face/FaceEnrollmentBox.kt`
- `app/src/main/java/com/example/secretlab/face/FaceInputPolicy.kt`
- `app/src/main/java/com/example/secretlab/face/FaceTrainingPolicy.kt`
- `app/src/main/java/com/example/secretlab/face/FaceBackboneSpec.kt`
- `app/src/main/java/com/example/secretlab/face/FaceModelRunner.kt`
- `app/src/test/java/com/example/secretlab/face/FaceEnrollmentBoxStudentTest.kt`
