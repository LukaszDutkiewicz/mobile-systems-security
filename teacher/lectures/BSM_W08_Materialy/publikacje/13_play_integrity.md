# Play Integrity

- Zrodlo: https://developer.android.com/google/play/integrity/overview
- Temat: sygnaly integralnosci urzadzenia

## Teza
- Play Integrity nie daje pewnosci absolutnej. Daje zestaw sygnalow, ktore backend moze wykorzystac do oceny, czy akcja pochodzi z autentycznej aplikacji i zaufanego urzadzenia.
- To jest narzedzie do polityki ryzyka, nie tylko do "checka".

## Co czytac
- Overview: czym sa integrity verdicts
- Device integrity / app integrity: jakie sygnaly dostaje backend
- Standard vs classic requests: kiedy i jak zadawac zapytanie
- RequestHash / nonce: jak zabezpieczyc zapytanie przed podrobieniem

## Frazy do znalezienia
- `deviceIntegrity`
- `appIntegrity`
- `accountDetails`
- `appAccessRiskVerdict`
- `playProtectVerdict`
- `recentDeviceActivity`
- `deviceRecall`
- `MEETS_DEVICE_INTEGRITY`
- `MEETS_STRONG_INTEGRITY`

## Co jest na stronie
- Dokumentacja mowi wprost, ze odpowiedz ma format verdictu, a nie prostego yes/no.
- Podkresla znaczenie momentu wykonania zapytania, zeby ograniczyc obejscia.
- Opisuje, jak hash lub nonce utrudnia tampering i replay.
- Dodatkowe verdicty sa przydatne, bo wskazuja na ryzyko overlay, accessibility abuse i automatyzacji.

## Co wyciagnac
- sygnały integralności jako wejście do polityki backendowej
- różnica między sygnałem a dowodem
- dobry most od root detection do twardej attestation
