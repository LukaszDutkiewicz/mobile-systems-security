# External storage in Android 11

- Zrodlo: https://developer.android.com/about/versions/11/privacy/storage
- Temat: ekspozycja na external storage

## Teza
- Android 11 dalej zaostrza model external storage, co dobrze pasuje do argumentu, ze wspoldzielony storage jest domyslnie bardziej ryzykowny niz storage aplikacyjny.
- To zrodlo daje praktyczny kontekst migracyjny, a nie tylko ogolny opis scoped storage.

## Co czytac
- Changes in Android 11
- `requestLegacyExternalStorage`
- Fragmenty o `READ_EXTERNAL_STORAGE` i nowych dialogach

## Frazy do znalezienia
- `requestLegacyExternalStorage`
- `scoped storage`
- `READ_EXTERNAL_STORAGE`
- `Android 11`

## Co jest na stronie
- Dokument pokazuje, ze nawet w Android 11 polityka external storage staje sie bardziej restrykcyjna.
- Wazne jest to, ze zachowanie zalezy od target SDK i opt-outu.
- To przydaje sie do slajdu o tym, ze bezpieczeństwo storage zmienia sie wraz z wersja platformy.

## Co wyciagnac
- ewolucje ryzyka external storage
- dlaczego przestarzale modele dostepu przestaja byc akceptowane
