# FileProvider

- Zrodlo: https://developer.android.com/reference/androidx/core/content/FileProvider
- Temat: bezpieczne udostepnianie plikow przez `content://`

## Teza
- `FileProvider` to bezpieczniejszy sposob przekazywania plikow innym aplikacjom niz `file://`, bo pozwala dawac tymczasowy dostep zamiast wystawiac caly plik systemowo.
- Kluczowe jest ograniczenie zasięgu: tylko wybrane katalogi, tylko na czas dzialania i tylko z wyrazna zgoda w `Intent`.

## Co czytac
- Overview: czym jest `FileProvider` i dlaczego jest lepszy niz `file://`
- Defining a FileProvider: konfiguracja manifestu, `android:exported="false"`, `grantUriPermissions="true"`
- Specifying Available Files: jak deklaruje sie katalogi w XML
- Granting Temporary Permissions to a URI: jak działaja flagi przy `Intent`

## Co jest na stronie
- Dokumentacja wyjasnia, ze `FileProvider` generuje `content://` URI dla pliku zamiast bezposredniej sciezki.
- W konfiguracji manifestu autorzy rekomenduja `exported=false`, bo provider nie ma byc publiczny.
- XML `paths` ogranicza, z jakich katalogow wolno generowac URI, co jest podstawowa kontrola ekspozycji.
- Sekcja o temporary permissions pokazuje, ze dostep ma byc przyznany tylko na czas potrzebny do realizacji zadania.

## Co wyciagnac
- roznica miedzy wystawieniem pliku a przekazaniem kontrolowanego URI
- dlaczego katalogi musza byc whitelistowane
- jak taki mechanizm wspiera temat bezpiecznego udostepniania danych lokalnych
