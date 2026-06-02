# PrivateDrop for Apple AirDrop

- Zrodlo: https://www.usenix.org/conference/usenixsecurity21/presentation/heinrich
- Temat: PrivateDrop i prywatne uwierzytelnianie w AirDrop

## Teza
- PrivateDrop pokazuje, ze klasyczne contact checks w AirDrop przeciekaja phone numbers i email addresses, a PSI moze to zastapic bez psucia UX.

## Co czytac
- Abstract
- design problem
- PSI-based mutual authentication
- performance evaluation

## Frazy do znalezienia
- `phone numbers`
- `email addresses`
- `private set intersection`
- `authentication delay`
- `AirDrop`

## Co jest na stronie
- Autorzy zidentyfikowali dwa flawy projektowe w auth AirDrop.
- Proponuja PSI-based protocol, ktory dziala offline i na ograniczonych zasobach.
- Wykaza, ze delay pozostaje ponizej jednej sekundy.

## Co wyciagnac
- jak wyglada zagrozenie w contacts-only mode
- gdzie PSI wchodzi do stacku
- jakie sa trade-offy wydajnosciowe

