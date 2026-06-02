# Key attestation hardware

- Zrodlo: https://developer.android.com/privacy-and-security/security-key-attestation
- Temat: sygnaly integralnosci urzadzenia

## Teza
- Hardware-backed attestation pokazuje, jak silniejszy dowod o stanie klucza i urzadzenia trafia do backendu.

## Co czytac
- ensure device supports hardware-level attestation
- retrieve and verify certificate chain
- `attestationSecurityLevel`

## Frazy do znalezienia
- `TrustedEnvironment`
- `StrongBox`
- `certificate chain`
- `KeyStore.getCertificateChain()`

## Co wyciagnac
- mocniejszy fundament zaufania niz local checks
