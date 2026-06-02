# Play Integrity verdicts

- Zrodlo: https://developer.android.com/google/play/integrity/verdicts
- Temat: sygnaly integralnosci urzadzenia

## Teza
- Same overview nie wystarcza; verdicts pokazuje, jakie konkretne sygnaly backend moze dostac, w tym app access risk i play protect verdict.
- To jest bardzo wazne, bo laczy integrity z overlay, accessibility i malware.

## Co czytac
- Environment details field
- App access risk verdict
- Play Protect verdict
- Przykłady interpretacji verdictow

## Frazy do znalezienia
- `environmentDetails`
- `appAccessRiskVerdict`
- `playProtectVerdict`
- `KNOWN_OVERLAYS`
- `KNOWN_CONTROLLING`
- `UNKNOWN_CAPTURING`

## Co jest na stronie
- Dokument wyjasnia, ze `environmentDetails` zawiera dane o ryzyku z aplikacji i ochronie Play Protect.
- Wprost opisuje aplikacje, ktore moga capture/overlay/control device.
- To idealny material, zeby powiazac Play Integrity z UI redressing i accessibility abuse.

## Co wyciagnac
- sygnaly bezpieczenstwa obejmujace nie tylko sam device, ale tez srodowisko
- mocny most do tematow 7, 8, 9 i 12
