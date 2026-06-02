# Key attestation chain

- Zrodlo: https://developer.android.com/privacy-and-security/security-key-attestation
- Temat: sygnaly integralnosci urzadzenia / atestacja klucza

## Teza
- To jest drugi, bardziej techniczny punkt widzenia na atestacje: nie tylko koncept, ale konkretna weryfikacja lancucha certyfikatow i poziomu security.
- Dobrze uzupelnia Play Integrity, bo pokazuje twardszy dowod po stronie hardware-backed trust.

## Co czytac
- Before you begin
- Retrieve and verify a hardware-backed key pair
- Certificate chain verification
- `attestationSecurityLevel`

## Frazy do znalezienia
- `attestation certificate chain`
- `Google attestation root key`
- `TrustedEnvironment`
- `StrongBox`
- `KeyStore.getCertificateChain()`

## Co jest na stronie
- Dokument mowi, ze trzeba sprawdzic lancuch certyfikatow i jego root.
- Kluczowe jest to, ze weryfikacje robi sie na zaufanym serwerze, a nie na tym samym urzadzeniu.
- To dobry kontrast do lekkich root checks: tu mamy konkretny lancuch zaufania.

## Co wyciagnac
- silniejszy sygnal niz zwykly device check
- praktyczny material do pokazania, czym jest hardware-backed attestation
