# InsecureNotes

Starter Android project for the lesson-H source-code scan exercise.

This project is intentionally small and obviously insecure. The notebook uses it to teach students how to identify common mobile security issues from source code and scanner output.

## What to inspect

- `app/src/main/java/com/example/secretlab/mfa/LabMfaFixture.kt`
- `app/src/main/java/com/example/secretlab/data/LocalAccountVault.kt`
- `app/src/main/java/com/example/secretlab/debug/LocalHashDemo.kt`
- `app/src/main/java/com/example/secretlab/debug/SecurityLogger.kt`
- `app/src/main/java/com/example/secretlab/MainActivity.kt`

## Exercise focus

- hardcoded fake secret
- plaintext token storage
- sensitive logging
- weak cryptography example

## Notebook answer codes

- `HARDCODED_SECRET`
- `PLAINTEXT_SHARED_PREFERENCES`
- `SENSITIVE_LOGGING`
- `WEAK_CRYPTO`

## Notes

- All secrets are fake.
- The project is only a teaching aid.
- Students should submit the canonical code listed in the notebook, not a scanner paragraph.
