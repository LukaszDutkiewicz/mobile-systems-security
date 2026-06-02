# Storage Access Framework

- Zrodlo: https://developer.android.com/guide/topics/providers/document-provider
- Temat: Storage Access Framework

## Teza
- SAF daje standaryzowany, sterowany przez uzytkownika sposob dostepu do dokumentow i plikow. To nie jest "bezpieczny folder", tylko politycznie kontrolowany kanal wyboru zasobu.
- W kontekście bezpieczenstwa najwazniejsze sa `DocumentsProvider` i persistable URI permissions.

## Co czytac
- Overview: czym jest SAF i jaki problem rozwiązuje
- Document provider: rola `DocumentsProvider`
- Persistable URI permissions: jak dostep moze przetrwac dluzej niz pojedynczy `Intent`
- Część o browse/open flow: jak wyglada standardowy przeplyw wyboru dokumentu

## Frazy do znalezienia
- `Storage Access Framework`
- `ACTION_OPEN_DOCUMENT`
- `ACTION_CREATE_DOCUMENT`
- `DocumentsProvider`
- `persistable URI permissions`

## Co jest na stronie
- Android wprowadza SAF, zeby aplikacje nie musialy same projektowac wlasnego UX do wyboru plikow.
- `DocumentsProvider` pozwala dostawcy storage udostepnic swoje dokumenty przez wspolny interfejs.
- Persistable permissions sa wazne, bo pokazują, ze dostep może byc celowo utrzymany, ale dalej kontrolowany.
- W praktyce SAF ogranicza chaos z wlasnymi pickerami i zmniejsza liczbe miejsc, w ktorych aplikacje trzymaja niekontrolowane kopie plikow.

## Co wyciagnac
- SAF jako mechanizm ograniczania ekspozycji danych
- odroznienie folderu aplikacji od modelu dokumentow
- dobre miejsce na pokazanie, jak system ogranicza eksport danych
