# FileProvider best practices

- Zrodlo: https://developer.android.com/privacy-and-security/security-best-practices
- Temat: FileProvider i bezpieczne udostepnianie plikow

## Teza
- Ten dokument jest dobrym trzeciim zrodlem dla FileProvider, bo pokazuje szersza zasade: nie wystawiaj publicznie komponentow ani danych, jesli wystarczy kontrolowany grant URI.
- W praktyce chodzi o to, zeby udostepnianie plikow bylo jawne, minimalne i czasowe.

## Co czytac
- Fragment o `android:exported` i komponentach wystawianych na zewnatrz
- Fragment o providerach i ryzyku zbyt szerokiego eksportu
- Fragmenty o bezpiecznym przechowywaniu danych lokalnych

## Frazy do znalezienia
- `android:exported`
- `content provider`
- `temporary permission`
- `private file area`

## Co jest na stronie
- Dokumentacja przypomina, ze komponenty nie powinny byc eksportowane bez potrzeby.
- Provider jest wskazany jako mechanizm lepszy niz szeroki dostep do plikow.
- To jest dobra podkladka pod argument, ze FileProvider to nie tylko technika, ale wyraz szerszej zasady minimalnego ujawniania.

## Co wyciagnac
- wspolna zasada z tematem URI grants: udostepniaj tylko to, co potrzebne
- dobry kontekst do pokazania, dlaczego `exported=false` ma znaczenie
