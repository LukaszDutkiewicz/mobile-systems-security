# SAF best practices

- Zrodlo: https://developer.android.com/training/data-storage/use-cases
- Temat: Storage Access Framework

## Teza
- Trzeci tekst do SAF jest potrzebny, bo use cases pokazuje, kiedy Android woli kontrolowane API do plikow, a kiedy lepiej nie trzymac danych wlasnym formatem.
- To wzmacnia teze, ze SAF nie jest wyłącznie interfejsem UX, tylko polityka zarzadzania plikami.

## Co czytac
- Use cases dotyczace dokumentow, mediow i plikow shared with user
- Fragmenty o scoped storage
- Fragmenty o tym, kiedy korzystac z systemowych pickerow

## Frazy do znalezienia
- `scoped storage`
- `share files`
- `user files`
- `documents`
- `media`

## Co jest na stronie
- Dokumentacja rozdziela przypadki uzycia plikow, mediow i dokumentow.
- Pokazuje, ze nie wszystko powinno byc przechowywane jako surowy plik z pelnym dostepem.
- To dobry argument dla tematu, ze systemowy picker i kontrolowany dostep sa bezpieczniejsze od wlasnych rozwiazan.

## Co wyciagnac
- kiedy uzyc SAF zamiast wlasnego dostepu do storage
- jak to wspiera ograniczanie ekspozycji danych
