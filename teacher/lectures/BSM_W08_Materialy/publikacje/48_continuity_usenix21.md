# Apple Continuity analysis

- Zrodlo: https://www.usenix.org/conference/usenixsecurity21/presentation/stute
- Temat: Apple continuity i cross-device services

## Teza
- Praca o Continuity pokazuje, ze Handoff, Universal Clipboard i Wi-Fi Password Sharing tworza duzy, zlozony stack protokolow z BLE, AWDL i Wi-Fi.

## Co czytac
- Abstract
- Section o reverse engineering guide
- Handoff, Universal Clipboard, Wi-Fi Password Sharing
- Analiza packetow i identifying information

## Frazy do znalezienia
- `Handoff`
- `Universal Clipboard`
- `Wi-Fi Password Sharing`
- `BLE`
- `AWDL`
- `identifying information`
- `track`

## Co jest na stronie
- Autorzy analizuja trzy uslugi Continuity i opisuja guide do structured analysis.
- Wskazuja na leakage identifying information, trackability, spoofing, relay i DoS.
- Pokazuja, ze reverse engineering i packet capture sa praktyczna metoda pracy z tym stackiem.

## Co wyciagnac
- state machine dla discovery/auth/transfer
- unencrypted metadata i fingerprinting
- punkt odniesienia do test matrix

