# Play Integrity standard requests

- Zrodlo: https://developer.android.com/google/play/integrity/standard
- Temat: sygnaly integralnosci urzadzenia

## Teza
- Standard requests sa potrzebne jako osobne zrodlo, bo pokazuja konkretna procedure zapytania i weryfikacji po stronie backendu.
- To zamyka temat sygnalow integralnosci od poziomu "co jest" do poziomu "jak to wywolac".

## Co czytac
- Request flow
- Standard vs classic
- Backend verification
- Nonce / request hash

## Frazy do znalezienia
- `request flow`
- `standard`
- `classic`
- `backend verification`
- `nonce`

## Co jest na stronie
- Dokument pokazuje pelny przeplyw: aplikacja, backend, weryfikacja.
- Roznica miedzy standard a classic jest wazna do omowienia kosztu integracji i stopnia kontroli.
- Weryfikacja backendowa jest kluczowa, bo sam klient nie powinien byc zrodlem prawdy.

## Co wyciagnac
- jak sygnaly integralnosci przechodza z urzadzenia na serwer
- dlaczego backend musi weryfikowac, a nie tylko przyjmowac odpowiedz klienta
