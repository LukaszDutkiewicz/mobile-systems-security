# Lesson G App

Starter Android app for the next mobile security lab.

This project continues the earlier Android labs and focuses on app provenance, runtime trust, and backup/migration hygiene.

## What is already in the starter

- a small map card that can load current location from an external map service once the API key is added
- photo picking from gallery
- photo capture from camera
- a student ID field
- a Kotlin answer-submission helper for the notebook flow
- a native helper that reads build-time secret material

## What stays for the lab work

- manifest and privacy audit work
- app provenance checks
- integrity-gated backend request handling
- secret hygiene under backup and migration

## Where the answers come from

### Task 1

- The app already sends this automatically.
- Enter the ID, then complete the required permission flow.
- When the permissions and the ID line up, the app submits the answer on its own.
- This is the manifest / privacy audit portion of the lab.

### Task 2

- The answer appears from the Android Studio evidence path.
- Run the unit tests or `./gradlew :app:bsmEvidence`.
- When the provenance checks are implemented correctly, the evidence task prints the short completion code.
- That means the app build identity matches the expected signing identity, tampering is rejected, and install-time trust is separated from runtime trust.

### Task 3

- The answer also appears from the Android Studio evidence path.
- Run the integrity-gated backend test and then `./gradlew :app:bsmEvidence`.
- When the request is correctly bound to the trusted app state, the evidence task prints the short completion code.
- That means the backend gate only accepts the request when the integrity verdict is valid, the package identity matches, and the request is bound to the app identity.

### Task 4

- The answer comes from the app-secret path after the backup and migration hygiene work is in place.
- The notebook cell reads it from the app state or from the secret store path after the missing security pieces are added.
- The starter already ships the Task 4 secret as an encrypted blob in `local.properties`.
- `local.properties` is only the transport location for that encrypted blob, not the protection itself.
- The map API key is the value that needs to be added later in the same encrypted form.
- The static map view uses Geoapify Static Maps, which has a free tier.
- Both values are decrypted through the native helper, which holds the algorithm and key material.
- To make the map render, create a free Geoapify project at `https://myprojects.geoapify.com/` and copy its API key.
- From the project root run `python3 tools/encrypt_secret_blob.py "YOUR_GEOAPIFY_API_KEY"` and copy the printed Base64 blob.
- Add that blob to `local.properties` as `map_api_key_b64=...`, then rebuild the app.

## Main files used by the notebook

- `app/src/main/java/com/example/secretlab/MainActivity.kt`
- `app/src/main/java/com/example/secretlab/lab/TaskCompletion.kt`
- `app/src/main/java/com/example/secretlab/secure/SecretBox.kt`
- `app/src/main/java/com/example/secretlab/secure/BiometricBoundSecretStore.kt`
- `app/src/main/java/com/example/secretlab/secure/AppSecrets.kt`
- `app/src/main/cpp/secret_keys.cpp`
- `app/src/main/AndroidManifest.xml`
- `app/src/main/res/xml/file_paths.xml`

## Notes

- The project is scaffolded for Android Studio.
- The Gradle wrapper JAR is not included in this workspace snapshot.
- The app is intentionally split between UI, security helpers, and test/evidence output instead of putting everything in `MainActivity.kt`.
