# Secure Deletion

- Plik: `teacher/lectures/BSM_W08_Materialy/papers/secure-deletion.pdf`
- Temat: retencja danych i bezpieczne usuwanie

## Teza
- Na log-structured file system `delete` nie oznacza fizycznego znikniecia danych.
- Autorzy pokazuja, ze klasyczne techniki secure deletion z block-structured FS nie przenosza sie na YAFFS.

## Co czytac
- Strony 1-2: abstract i problem 44 godzin / brak gwarancji usuniecia
- Strony 2-4: system model i background YAFFS
- Strony 4-7: dlaczego overwrite i encryption nie wystarcza w log-structured FS
- Strony 7-9: purging, ballooning, zero overwriting
- Strony 9-11: wyniki i trade-offy

## Co jest na tych stronach
- W abstract pada najwazniejszy wynik: dane moga pozostawac widoczne ok. 44 godziny lub dluzej.
- System model pokazuje, dlaczego selektywne kasowanie jest realnym use-case na telefonie.
- Background o YAFFS wyjasnia, czemu log-structured storage zachowuje stare wersje danych.
- Czesc o rozwiazaniach opisuje trzy mechanizmy i ich koszty: czas, wear i wymagane uprawnienia.
- Wyniki eksperymentalne sa potrzebne, bo bez nich temat bylby tylko teoretyczny.

## Co wyciagnac
- dlaczego "delete" nie znaczy "gone"
- jak log-structured FS utrudnia kasanie
- trzy mechanizmy secure deletion i ich koszty
- retencja danych jako realny problem na telefonie
- most do tematu polityk retencji i data lifecycle
