# External storage exposure

- Zrodlo 1: https://developer.android.com/training/data-storage
- Zrodlo 2: https://developer.android.com/guide/practices/security
- Temat: ekspozycja na external storage

## Teza
- External storage nie jest prywatnym magazynem aplikacji. To miejsce, w ktorym inne aplikacje i uzytkownik moga miec dostep, wiec nie wolno tam traktowac danych jak sekretu.
- Temat jest wazny, bo storage zewnetrzny miesza sie z DCL, plikami tymczasowymi i kopiowaniem danych przez system.

## Co czytac
- Data and file storage overview: internal vs external vs scoped storage
- Security checklist: sections o insecure storage locations i dynamically loaded code
- Fragmenty o scoped storage: co sie zmienilo od Android 10

## Co jest na stronie
- Android opisuje, ze nowe wersje wprowadzily scoped storage, aby ograniczyc dostep do plikow na zewnetrznym storage.
- Security checklist laczy external storage z ryzykiem modyfikacji plikow przez inne aplikacje lub siec.
- Dokumentacja wskazuje, ze kod z takich lokalizacji moze zostac podmieniony, wiec nie jest to tylko problem "danych", ale tez integralnosci.

## Co wyciagnac
- zewnetrzny storage jako miejsce wspoldzielone i podatne
- powiazanie z code injection i utrata integralnosci
- dobre wejscie do tematu "gdzie aplikacja powinna trzymac sekrety"
