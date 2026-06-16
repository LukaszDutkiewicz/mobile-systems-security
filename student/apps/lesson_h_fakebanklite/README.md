# FakeBankLite

Starter Android project for the APK and manifest analysis exercise.

This project is intentionally insecure so students can practice reading APK-level findings from MobSF or a similar scanner.

## What to inspect

- `app/src/main/AndroidManifest.xml`
- `app/src/main/java/com/example/secretlab/MainActivity.kt`
- `app/src/main/java/com/example/secretlab/AdminActivity.kt`

## Exercise focus

- cleartext traffic enabled
- backup enabled
- debuggable build flag
- exported component

## Notebook answer codes

- `CLEARTEXT_TRAFFIC`
- `BACKUP_ENABLED`
- `DEBUGGABLE_TRUE`
- `EXPORTED_COMPONENT`
