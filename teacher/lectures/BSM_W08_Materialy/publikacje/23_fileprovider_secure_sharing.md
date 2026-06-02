# FileProvider secure sharing

- Zrodlo: https://developer.android.com/training/secure-file-sharing/setup-sharing
- Temat: FileProvider

## Teza
- To najlepszy trzeci tekst do FileProvider, bo jest praktyczny: mowi jak bezpiecznie oferowac plik innej aplikacji.
- Wspiera wniosek, ze secure sharing to przede wszystkim content URI i kontrolowany manifest, nie surowa sciezka do pliku.

## Co czytac
- Wstep o secure file sharing
- Fragment o content URI
- Fragment o definiowaniu `FileProvider` i katalogow do udostepniania

## Frazy do znalezienia
- `content URI`
- `FileProvider`
- `manifest`
- `share files securely`

## Co jest na stronie
- Dokument jasno mowi, ze do bezpiecznego udostepnienia trzeba wystawic handle w formie content URI.
- Po konfiguracji w manifest trzeba wskazac katalogi, z ktorych wolno tworzyc URI.
- To dobre zrodlo do pokazania, jak praktyka pokrywa sie z API reference.

## Co wyciagnac
- bezpieczne udostepnianie plikow jako model czasowego i ograniczonego dostepu
