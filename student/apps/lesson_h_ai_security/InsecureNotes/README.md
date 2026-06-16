# InsecureNotes

Source-code analysis target for `H01` and `H03`.

## Intentionally insecure elements

- fake API key hardcoded in Kotlin
- token stored in plaintext preferences
- sensitive values written to logs
- weak crypto example

## Suggested files

- `MainActivity.kt`
- `SecretStore.kt`
- `CryptoHelper.kt`
- `LoggingHelper.kt`

## Canonical answer codes

- `HARDCODED_SECRET`
- `PLAINTEXT_SHARED_PREFERENCES`
- `SENSITIVE_LOGGING`
- `WEAK_CRYPTO`
