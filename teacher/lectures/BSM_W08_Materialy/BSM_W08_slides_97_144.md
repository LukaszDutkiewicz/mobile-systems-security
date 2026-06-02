#slide 97
## layout
definition
## slide title
Why DCL exists
## subtitle
Co to jest
## term
Why DCL exists
## definition
DCL istnieje po to, by obsłużyć modularność, pluginy i runtime updates.
## teleprompter:
DCL istnieje po to, by obsłużyć modularność, pluginy i runtime updates.
Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła. Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji. DCL istnieje po to, by obsłużyć modularność, pluginy i runtime updates. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 98
## layout
bullet
## slide title
Why DCL exists
## subtitle
Jak działa
## bullets
- Why DCL exists: Oficjalny dokument Androida mówi wprost żeby unikać dynamic…
- Why DCL exists: Dynamiczne ładowanie kodu jest potrzebne do pluginów i…
- Why DCL exists: Obrona wymaga verify-before-load sprawdzenia trusted sources odrzucenia pliku…
## teleprompter:
Why DCL exists zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 99
## layout
bullet
## slide title
Why DCL exists
## subtitle
Jak pęka
## bullets
- Why DCL exists: Atak pojawia się w momencie gdy ktoś podmieni…
- Why DCL exists: Oficjalny dokument Androida mówi wprost żeby unikać dynamic…
- Why DCL exists: Dynamiczne ładowanie kodu jest potrzebne do pluginów i…
## teleprompter:
Why DCL exists przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 100
## layout
bullet
## slide title
Why DCL exists
## subtitle
Jak się bronić
## bullets
- Why DCL exists: Obrona wymaga verify-before-load sprawdzenia trusted sources odrzucenia pliku…
- Why DCL exists: Oficjalny dokument Androida mówi wprost żeby unikać dynamic…
- Why DCL exists: Atak pojawia się w momencie gdy ktoś podmieni…
## teleprompter:
Why DCL exists wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

#slide 101
## layout
definition
## slide title
Attack surface
## subtitle
Co to jest
## term
Attack surface
## definition
Powierzchnia ataku rośnie w chwili, gdy ładowany kod da się podmienić lub uszkodzić.
## teleprompter:
Powierzchnia ataku rośnie w chwili, gdy ładowany kod da się podmienić lub uszkodzić.
Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła. Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji. Powierzchnia ataku rośnie w chwili, gdy ładowany kod da się podmienić lub uszkodzić. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 102
## layout
bullet
## slide title
Attack surface
## subtitle
Jak działa
## bullets
- Attack surface: Oficjalny dokument Androida mówi wprost żeby unikać dynamic…
- Attack surface: Dynamiczne ładowanie kodu jest potrzebne do pluginów i…
- Attack surface: Obrona wymaga verify-before-load sprawdzenia trusted sources odrzucenia pliku…
## teleprompter:
Attack surface zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 103
## layout
bullet
## slide title
Attack surface
## subtitle
Jak pęka
## bullets
- Attack surface: Atak pojawia się w momencie gdy ktoś podmieni…
- Attack surface: Oficjalny dokument Androida mówi wprost żeby unikać dynamic…
- Attack surface: Dynamiczne ładowanie kodu jest potrzebne do pluginów i…
## teleprompter:
Attack surface przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 104
## layout
bullet
## slide title
Attack surface
## subtitle
Jak się bronić
## bullets
- Attack surface: Obrona wymaga verify-before-load sprawdzenia trusted sources odrzucenia pliku…
- Attack surface: Oficjalny dokument Androida mówi wprost żeby unikać dynamic…
- Attack surface: Atak pojawia się w momencie gdy ktoś podmieni…
## teleprompter:
Attack surface wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

#slide 105
## layout
definition
## slide title
Remote source risk
## subtitle
Co to jest
## term
Remote source risk
## definition
Remote code loading jest najdroższe z punktu widzenia ryzyka i może łamać Google Play policy.
## teleprompter:
Remote code loading jest najdroższe z punktu widzenia ryzyka i może łamać Google Play policy.
Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła. Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji. Remote code loading jest najdroższe z punktu widzenia ryzyka i może łamać Google Play policy. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 106
## layout
bullet
## slide title
Remote source risk
## subtitle
Jak działa
## bullets
- Remote source risk: Oficjalny dokument Androida mówi wprost żeby unikać dynamic…
- Remote source risk: Dynamiczne ładowanie kodu jest potrzebne do pluginów i…
- Remote source risk: Obrona wymaga verify-before-load sprawdzenia trusted sources odrzucenia pliku…
## teleprompter:
Remote source risk zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 107
## layout
bullet
## slide title
Remote source risk
## subtitle
Jak pęka
## bullets
- Remote source risk: Atak pojawia się w momencie gdy ktoś podmieni…
- Remote source risk: Oficjalny dokument Androida mówi wprost żeby unikać dynamic…
- Remote source risk: Dynamiczne ładowanie kodu jest potrzebne do pluginów i…
## teleprompter:
Remote source risk przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 108
## layout
bullet
## slide title
Remote source risk
## subtitle
Jak się bronić
## bullets
- Remote source risk: Obrona wymaga verify-before-load sprawdzenia trusted sources odrzucenia pliku…
- Remote source risk: Oficjalny dokument Androida mówi wprost żeby unikać dynamic…
- Remote source risk: Atak pojawia się w momencie gdy ktoś podmieni…
## teleprompter:
Remote source risk wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

#slide 109
## layout
definition
## slide title
Trusted storage
## subtitle
Co to jest
## term
Trusted storage
## definition
Kod, który ma być później ładowany, powinien lądować w internal storage albo w scoped storage.
## teleprompter:
Kod, który ma być później ładowany, powinien lądować w internal storage albo w scoped storage.
Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła. Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji. Kod, który ma być później ładowany, powinien lądować w internal storage albo w scoped storage. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 110
## layout
bullet
## slide title
Trusted storage
## subtitle
Jak działa
## bullets
- Trusted storage: Oficjalny dokument Androida mówi wprost żeby unikać dynamic…
- Trusted storage: Dynamiczne ładowanie kodu jest potrzebne do pluginów i…
- Trusted storage: Obrona wymaga verify-before-load sprawdzenia trusted sources odrzucenia pliku…
## teleprompter:
Trusted storage zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 111
## layout
bullet
## slide title
Trusted storage
## subtitle
Jak pęka
## bullets
- Trusted storage: Atak pojawia się w momencie gdy ktoś podmieni…
- Trusted storage: Oficjalny dokument Androida mówi wprost żeby unikać dynamic…
- Trusted storage: Dynamiczne ładowanie kodu jest potrzebne do pluginów i…
## teleprompter:
Trusted storage przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 112
## layout
bullet
## slide title
Trusted storage
## subtitle
Jak się bronić
## bullets
- Trusted storage: Obrona wymaga verify-before-load sprawdzenia trusted sources odrzucenia pliku…
- Trusted storage: Oficjalny dokument Androida mówi wprost żeby unikać dynamic…
- Trusted storage: Atak pojawia się w momencie gdy ktoś podmieni…
## teleprompter:
Trusted storage wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

#slide 113
## layout
definition
## slide title
External storage risk
## subtitle
Co to jest
## term
External storage risk
## definition
Shared external storage jest mutowalny, więc nie nadaje się na artefakt wykonywalny.
## teleprompter:
Shared external storage jest mutowalny, więc nie nadaje się na artefakt wykonywalny.
Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła. Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji. Shared external storage jest mutowalny, więc nie nadaje się na artefakt wykonywalny. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 114
## layout
bullet
## slide title
External storage risk
## subtitle
Jak działa
## bullets
- External storage risk: Oficjalny dokument Androida mówi wprost żeby unikać dynamic…
- External storage risk: Dynamiczne ładowanie kodu jest potrzebne do pluginów i…
- External storage risk: Obrona wymaga verify-before-load sprawdzenia trusted sources odrzucenia pliku…
## teleprompter:
External storage risk zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 115
## layout
bullet
## slide title
External storage risk
## subtitle
Jak pęka
## bullets
- External storage risk: Atak pojawia się w momencie gdy ktoś podmieni…
- External storage risk: Oficjalny dokument Androida mówi wprost żeby unikać dynamic…
- External storage risk: Dynamiczne ładowanie kodu jest potrzebne do pluginów i…
## teleprompter:
External storage risk przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 116
## layout
bullet
## slide title
External storage risk
## subtitle
Jak się bronić
## bullets
- External storage risk: Obrona wymaga verify-before-load sprawdzenia trusted sources odrzucenia pliku…
- External storage risk: Oficjalny dokument Androida mówi wprost żeby unikać dynamic…
- External storage risk: Atak pojawia się w momencie gdy ktoś podmieni…
## teleprompter:
External storage risk wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

#slide 117
## layout
definition
## slide title
Integrity before load
## subtitle
Co to jest
## term
Integrity before load
## definition
Bezpieczny wzorzec to verify-before-load, a nie load-first.
## teleprompter:
Bezpieczny wzorzec to verify-before-load, a nie load-first.
Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła. Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji. Bezpieczny wzorzec to verify-before-load, a nie load-first. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 118
## layout
bullet
## slide title
Integrity before load
## subtitle
Jak działa
## bullets
- Integrity before load: Oficjalny dokument Androida mówi wprost żeby unikać dynamic…
- Integrity before load: Dynamiczne ładowanie kodu jest potrzebne do pluginów i…
- Integrity before load: Obrona wymaga verify-before-load sprawdzenia trusted sources odrzucenia pliku…
## teleprompter:
Integrity before load zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 119
## layout
bullet
## slide title
Integrity before load
## subtitle
Jak pęka
## bullets
- Integrity before load: Atak pojawia się w momencie gdy ktoś podmieni…
- Integrity before load: Oficjalny dokument Androida mówi wprost żeby unikać dynamic…
- Integrity before load: Dynamiczne ładowanie kodu jest potrzebne do pluginów i…
## teleprompter:
Integrity before load przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 120
## layout
bullet
## slide title
Integrity before load
## subtitle
Jak się bronić
## bullets
- Integrity before load: Obrona wymaga verify-before-load sprawdzenia trusted sources odrzucenia pliku…
- Integrity before load: Oficjalny dokument Androida mówi wprost żeby unikać dynamic…
- Integrity before load: Atak pojawia się w momencie gdy ktoś podmieni…
## teleprompter:
Integrity before load wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

#slide 121
## layout
definition
## slide title
SHA-256 checker
## subtitle
Co to jest
## term
SHA-256 checker
## definition
SHA-256 checker liczy digest i porównuje go z referencją zaufaną przez aplikację.
## teleprompter:
SHA-256 checker liczy digest i porównuje go z referencją zaufaną przez aplikację.
Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła. Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji. SHA-256 checker liczy digest i porównuje go z referencją zaufaną przez aplikację. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 122
## layout
bullet
## slide title
SHA-256 checker
## subtitle
Jak działa
## bullets
- SHA-256 checker: Oficjalny dokument Androida mówi wprost żeby unikać dynamic…
- SHA-256 checker: Dynamiczne ładowanie kodu jest potrzebne do pluginów i…
- SHA-256 checker: Obrona wymaga verify-before-load sprawdzenia trusted sources odrzucenia pliku…
## teleprompter:
SHA-256 checker zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 123
## layout
bullet
## slide title
SHA-256 checker
## subtitle
Jak pęka
## bullets
- SHA-256 checker: Atak pojawia się w momencie gdy ktoś podmieni…
- SHA-256 checker: Oficjalny dokument Androida mówi wprost żeby unikać dynamic…
- SHA-256 checker: Dynamiczne ładowanie kodu jest potrzebne do pluginów i…
## teleprompter:
SHA-256 checker przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 124
## layout
bullet
## slide title
SHA-256 checker
## subtitle
Jak się bronić
## bullets
- SHA-256 checker: Obrona wymaga verify-before-load sprawdzenia trusted sources odrzucenia pliku…
- SHA-256 checker: Oficjalny dokument Androida mówi wprost żeby unikać dynamic…
- SHA-256 checker: Atak pojawia się w momencie gdy ktoś podmieni…
## teleprompter:
SHA-256 checker wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

#slide 125
## layout
definition
## slide title
Code signing
## subtitle
Co to jest
## term
Code signing
## definition
Podpis kodu dodaje podpis kryptograficzny i zaufany public key.
## teleprompter:
Podpis kodu dodaje podpis kryptograficzny i zaufany public key.
Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła. Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji. Podpis kodu dodaje podpis kryptograficzny i zaufany public key. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 126
## layout
bullet
## slide title
Code signing
## subtitle
Jak działa
## bullets
- Code signing: Oficjalny dokument Androida mówi wprost żeby unikać dynamic…
- Code signing: Dynamiczne ładowanie kodu jest potrzebne do pluginów i…
- Code signing: Obrona wymaga verify-before-load sprawdzenia trusted sources odrzucenia pliku…
## teleprompter:
Code signing zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 127
## layout
bullet
## slide title
Code signing
## subtitle
Jak pęka
## bullets
- Code signing: Atak pojawia się w momencie gdy ktoś podmieni…
- Code signing: Oficjalny dokument Androida mówi wprost żeby unikać dynamic…
- Code signing: Dynamiczne ładowanie kodu jest potrzebne do pluginów i…
## teleprompter:
Code signing przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 128
## layout
bullet
## slide title
Code signing
## subtitle
Jak się bronić
## bullets
- Code signing: Obrona wymaga verify-before-load sprawdzenia trusted sources odrzucenia pliku…
- Code signing: Oficjalny dokument Androida mówi wprost żeby unikać dynamic…
- Code signing: Atak pojawia się w momencie gdy ktoś podmieni…
## teleprompter:
Code signing wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

#slide 129
## layout
definition
## slide title
Hash storage
## subtitle
Co to jest
## term
Hash storage
## definition
Referencja hash lub signature musi leżeć w chronionym miejscu, a nie obok samego payloadu.
## teleprompter:
Referencja hash lub signature musi leżeć w chronionym miejscu, a nie obok samego payloadu.
Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła. Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji. Referencja hash lub signature musi leżeć w chronionym miejscu, a nie obok samego payloadu. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 130
## layout
bullet
## slide title
Hash storage
## subtitle
Jak działa
## bullets
- Hash storage: Oficjalny dokument Androida mówi wprost żeby unikać dynamic…
- Hash storage: Dynamiczne ładowanie kodu jest potrzebne do pluginów i…
- Hash storage: Obrona wymaga verify-before-load sprawdzenia trusted sources odrzucenia pliku…
## teleprompter:
Hash storage zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 131
## layout
bullet
## slide title
Hash storage
## subtitle
Jak pęka
## bullets
- Hash storage: Atak pojawia się w momencie gdy ktoś podmieni…
- Hash storage: Oficjalny dokument Androida mówi wprost żeby unikać dynamic…
- Hash storage: Dynamiczne ładowanie kodu jest potrzebne do pluginów i…
## teleprompter:
Hash storage przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 132
## layout
bullet
## slide title
Hash storage
## subtitle
Jak się bronić
## bullets
- Hash storage: Obrona wymaga verify-before-load sprawdzenia trusted sources odrzucenia pliku…
- Hash storage: Oficjalny dokument Androida mówi wprost żeby unikać dynamic…
- Hash storage: Atak pojawia się w momencie gdy ktoś podmieni…
## teleprompter:
Hash storage wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

#slide 133
## layout
definition
## slide title
Path to execution
## subtitle
Co to jest
## term
Path to execution
## definition
Niebezpieczna ścieżka to download, write, verify, load i execute.
## teleprompter:
Niebezpieczna ścieżka to download, write, verify, load i execute.
Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła. Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji. Niebezpieczna ścieżka to download, write, verify, load i execute. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 134
## layout
bullet
## slide title
Path to execution
## subtitle
Jak działa
## bullets
- Path to execution: Oficjalny dokument Androida mówi wprost żeby unikać dynamic…
- Path to execution: Dynamiczne ładowanie kodu jest potrzebne do pluginów i…
- Path to execution: Obrona wymaga verify-before-load sprawdzenia trusted sources odrzucenia pliku…
## teleprompter:
Path to execution zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 135
## layout
bullet
## slide title
Path to execution
## subtitle
Jak pęka
## bullets
- Path to execution: Atak pojawia się w momencie gdy ktoś podmieni…
- Path to execution: Oficjalny dokument Androida mówi wprost żeby unikać dynamic…
- Path to execution: Dynamiczne ładowanie kodu jest potrzebne do pluginów i…
## teleprompter:
Path to execution przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 136
## layout
bullet
## slide title
Path to execution
## subtitle
Jak się bronić
## bullets
- Path to execution: Obrona wymaga verify-before-load sprawdzenia trusted sources odrzucenia pliku…
- Path to execution: Oficjalny dokument Androida mówi wprost żeby unikać dynamic…
- Path to execution: Atak pojawia się w momencie gdy ktoś podmieni…
## teleprompter:
Path to execution wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

#slide 137
## layout
definition
## slide title
Class loader choices
## subtitle
Co to jest
## term
Class loader choices
## definition
DexClassLoader, PathClassLoader i InMemoryDexClassLoader różnią się tym, skąd biorą kod i jak długo go trzymają.
## teleprompter:
DexClassLoader, PathClassLoader i InMemoryDexClassLoader różnią się tym, skąd biorą kod i jak długo go trzymają.
Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła. Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji. DexClassLoader, PathClassLoader i InMemoryDexClassLoader różnią się tym, skąd biorą kod i jak długo go trzymają. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 138
## layout
bullet
## slide title
Class loader choices
## subtitle
Jak działa
## bullets
- Class loader choices: Oficjalny dokument Androida mówi wprost żeby unikać dynamic…
- Class loader choices: Dynamiczne ładowanie kodu jest potrzebne do pluginów i…
- Class loader choices: Obrona wymaga verify-before-load sprawdzenia trusted sources odrzucenia pliku…
## teleprompter:
Class loader choices zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 139
## layout
bullet
## slide title
Class loader choices
## subtitle
Jak pęka
## bullets
- Class loader choices: Atak pojawia się w momencie gdy ktoś podmieni…
- Class loader choices: Oficjalny dokument Androida mówi wprost żeby unikać dynamic…
- Class loader choices: Dynamiczne ładowanie kodu jest potrzebne do pluginów i…
## teleprompter:
Class loader choices przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane.
Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.
Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany.
Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi.

#slide 140
## layout
bullet
## slide title
Class loader choices
## subtitle
Jak się bronić
## bullets
- Class loader choices: Obrona wymaga verify-before-load sprawdzenia trusted sources odrzucenia pliku…
- Class loader choices: Oficjalny dokument Androida mówi wprost żeby unikać dynamic…
- Class loader choices: Atak pojawia się w momencie gdy ktoś podmieni…
## teleprompter:
Class loader choices wymaga konkretnej reguły i miejsca egzekwowania.
Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.
Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu.
Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie.

#slide 141
## layout
definition
## slide title
Native versus Java
## subtitle
Co to jest
## term
Native versus Java
## definition
Natywne dlopen i dlsym mają ten sam problem z podmianą co loading pliku dex.
## teleprompter:
W obu ścieżkach najpierw pojawia się artefakt, potem weryfikacja, a dopiero potem wykonanie. W Java tym artefaktem jest dex, a w native biblioteka `.so` ładowana przez `dlopen` i `dlsym`. Różnica leży w interfejsie, nie w modelu ryzyka: jeśli źródło nie jest zaufane, ścieżka kończy się tak samo.

#slide 142
## layout
bullet
## slide title
Native versus Java
## subtitle
Jak działa
## bullets
- dex przechodzi przez loader
- `.so` przechodzi przez `dlopen`
- integralność sprawdza się wcześniej
## teleprompter:
Ścieżka Java kończy się na loaderze klas, a ścieżka natywna na `dlopen` i `dlsym`. W obu przypadkach kolejność jest ta sama: pobranie, zapis, sprawdzenie referencji, dopiero potem load. Jeśli referencja hash albo podpis leży obok payloadu, nie chroni przed podmianą.

#slide 143
## layout
bullet
## slide title
Native versus Java
## subtitle
Jak pęka
## bullets
- zamiana pliku przed verify
- katalog współdzielony
- kod z sieci bez kontroli
## teleprompter:
Pęknięcie zaczyna się od podmiany pliku przed weryfikacją. Wystarczy katalog współdzielony albo pobranie z sieci bez kontroli pochodzenia, żeby code execution był tylko kwestią czasu. W praktyce exploit nie potrzebuje złożonego łańcucha, tylko niekontrolowanego pliku i zaufania do nazwy.

#slide 144
## layout
bullet
## slide title
Native versus Java
## subtitle
Jak się bronić
## bullets
- ta sama reguła dla dex i `.so`
- fallback po błędnym podpisie
- testy podmiany oraz braku odczytu
## teleprompter:
Obrona nie może rozróżniać Java i native w kwestii zaufania: dla obu obowiązuje verify-before-load i odrzucenie artefaktu po złym podpisie. Jeśli moduł ma się aktualizować dynamicznie, trzeba mieć bezpieczny fallback i możliwość rollbacku. Test powinien sprawdzić podmianę, błędny digest i sytuację, w której pliku nie da się w ogóle odczytać.
