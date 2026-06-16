#slide 1
## layout
title
## slide title
Poza uprawnieniami
## subtitle
Prywatność jako przepływ danych, zgoda i egzekwowanie polityk
## teleprompter:
Ten wykład nie zaczyna się od jednego mechanizmu obrony, tylko od trzech różnych warstw kontroli, które w praktyce często są ze sobą mylone. Pierwsza warstwa to uprawnienia systemowe, czyli to, co Android sprawdza na poziomie technicznym, zanim aplikacja dostanie dostęp do zasobu. Druga warstwa to zgoda użytkownika, czyli to, co wymaga prawo, gdy dane mają trafić do podmiotów trzecich albo być użyte w określonym celu. Trzecia warstwa to egzekwowanie polityki, czyli to, czy reguła istnieje tylko na papierze, czy da się ją naprawdę wymusić w działającym systemie.

To rozróżnienie jest ważne, bo każda z tych warstw może być obecna, a mimo to dane nadal mogą wyciekać. Aplikacja może mieć poprawnie zadeklarowane uprawnienie, ale nadal przesyłać dane przez inną ścieżkę. Może pokazać dialog zgody, ale użyć wzorca interfejsu, który w praktyce nie daje realnej odmowy. Może też opisać politykę bezpieczeństwa, ale nie mieć mechanizmu, który tę politykę rzeczywiście egzekwuje w konkretnym momencie wykonania.

Cały wykład będzie więc prowadzony tak, aby za każdym razem zadawać to samo pytanie: nie czy kontrola istnieje, tylko co ona realnie blokuje, co tylko sygnalizuje, a czego w ogóle nie widzi. Taki sposób myślenia pozwala połączyć trzy badawcze wątki, które będziemy później rozwijać: obejścia modelu uprawnień, naruszenia wymogu wcześniejszej zgody oraz problemy z tym, jak użytkownikowi pokazuje się wybór i jak system reaguje na ten wybór.

#slide 2
## layout
bullet
## slide title
Oś wykładu
## bullets
- co technicznie blokują uprawnienia, a czego nie blokują
- co prawo uznaje za uprzednią zgodę, a czego nie uznaje
- co interfejs pokazuje użytkownikowi, a co dzieje się po jego decyzji
- dlaczego sama deklaracja nie jest jeszcze dowodem zgodności
## teleprompter:
Ta sekcja ma ustawić wspólny język dla całego wykładu. Chcemy od początku rozdzielić trzy pytania, które w praktyce są często mieszane w jedną intuicję „system bezpieczeństwa”. Pytanie pierwsze brzmi: co dokładnie blokuje warstwa uprawnień? Ona blokuje dostęp do wskazanych zasobów i wywołań, ale nie jest równoznaczna z całkowitym powstrzymaniem przepływu informacji. Pytanie drugie brzmi: co prawo uznaje za zgodę? Tu nie chodzi o przypadkowe kliknięcie ani o zapis w regulaminie, tylko o zgodę wyraźną, uprzednią, poinformowaną, konkretną i jednoznaczną. Pytanie trzecie brzmi: co interfejs pokazuje użytkownikowi, a co faktycznie robi aplikacja po decyzji? To jest różnica między deklaracją a zachowaniem.

Ważne jest też, że wykład nie będzie się opierał na jednej metodzie dowodzenia. Jedne publikacje mierzą ruch sieciowy i brak zgody przed transferem danych. Inne analizują konfigurację i treść dialogów zgody. Jeszcze inne łączą analizę statyczną i dynamiczną, żeby znaleźć miejsca, w których mechanizmy ochrony są obchodzone. Ten wykład korzysta z tego zestawu metod po to, żeby nie mylić „wydaje się bezpieczne” z „jest bezpieczne”.

Z tego powodu oś wykładu jest prosta: najpierw ustalamy, gdzie są granice techniczne, potem gdzie są granice prawne, a na końcu sprawdzamy, czy granice użytkowe naprawdę prowadzą do egzekwowalnej polityki. Jeśli któryś z tych elementów nie działa, cała konstrukcja jest krucha.

#slide 3
## layout
bullet
## slide title
Trzy warstwy kontroli
## bullets
- warstwa techniczna: dostęp do zasobu i wymuszenie reguły
- warstwa prawna: podstawa przetwarzania i wcześniejsza zgoda
- warstwa interfejsu: sposób przedstawienia wyboru użytkownikowi
- warstwa operacyjna: czy decyzja w ogóle zmienia zachowanie systemu
## teleprompter:
W tej części trzeba wyraźnie rozdzielić cztery poziomy, bo bez tego bardzo łatwo przypisać jednemu mechanizmowi właściwości innego. Warstwa techniczna odpowiada za to, co system może fizycznie zablokować lub dopuścić. To jest poziom uprawnień, reguł dostępu i monitorowania wykonania. Warstwa prawna odpowiada za to, czy w ogóle wolno przetwarzać dane w danym celu i w danym momencie. Warstwa interfejsu odpowiada za to, w jaki sposób użytkownik dowiaduje się o operacji i czy ma realny wybór. Warstwa operacyjna odpowiada za to, czy po kliknięciu lub odmowie coś rzeczywiście się zmienia.

To rozróżnienie jest kluczowe, bo bardzo wiele systemów „ma wszystko”, a mimo to nie działa. Aplikacja może mieć formalnie poprawny mechanizm uprawnień, ale jeśli transfer danych przechodzi innym kanałem, techniczna kontrola niczego nie zatrzymuje. Aplikacja może pokazać dialog zgodny z wymaganiami, ale jeśli odmowa nie zmienia zachowania programu, wtedy warstwa interfejsu nie przekłada się na warstwę operacyjną. Można też mieć dokument prawny, ale jeżeli użytkownik nie dostał realnej informacji albo informacja była ukryta w praktyce, to zgoda nie spełnia swojego celu.

W tym wykładzie będziemy stale sprawdzać te cztery poziomy razem. To pozwala odróżnić błąd projektowy, błąd implementacyjny, błąd interfejsu i błąd zgodności prawnej. To są różne klasy problemów i nie wolno ich wrzucać do jednego worka, bo wtedy nie wiadomo, jaką obronę w ogóle projektować.

#slide 4
## layout
bullet
## slide title
Źródła i dane
## bullets
- obserwacja ruchu sieciowego aplikacji
- porównanie zachowania z deklarowanymi uprawnieniami
- analiza dialogów, dokumentów i zachowania po decyzji
- łączenie pomiaru technicznego z interpretacją prawną
## teleprompter:
Publikacje, na których opiera się ten wykład, mają wspólną cechę: żadna z nich nie zadowala się samą deklaracją. W każdym przypadku badacze porównują to, co aplikacja mówi albo deklaruje, z tym, co rzeczywiście robi. Czasem oznacza to analizę ruchu sieciowego i sprawdzenie, czy dane wychodzą z urządzenia bez odpowiedniej podstawy. Czasem oznacza to analizę dialogu zgody i sprawdzenie, czy użytkownik ma realną możliwość odmowy. Czasem oznacza to połączenie wyniku technicznego z klasyfikacją prawną odbiorcy danych.

To jest bardzo ważna metoda myślenia: najpierw obserwujemy zachowanie, potem dopiero pytamy, jak to zachowanie ma się do reguł. Dzięki temu można mówić nie tylko o tym, że coś „wygląda na nieprawidłowe”, ale o tym, dlaczego jest nieprawidłowe, na jakiej podstawie i w jakiej skali. Właśnie dlatego w kolejnych slajdach będziemy traktować badania jako dwa komplementarne narzędzia: jedno wykrywa zjawisko, drugie nadaje mu znaczenie.

Ten wykład korzysta z trzech rodzajów danych: z danych o zachowaniu aplikacji, z danych o treści i strukturze dialogów oraz z danych o tym, czy przepływ danych można prawnie i technicznie uzasadnić. Bez tego zestawu nie da się sensownie zbudować dalszej części kursu, bo wtedy zostaje tylko opinia, a nie analiza.

#slide 5
## layout
definition
## term
Uprawnienie
## definition
Systemowa zgoda na dostęp do wskazanego zasobu lub operacji, sprawdzana przez platformę przed wykonaniem akcji.
## teleprompter:
Uprawnienie to nie jest ogólna „zgoda systemu na wszystko”, tylko bardzo konkretna reguła, która dopuszcza lub blokuje wskazaną operację. W Androidzie model uprawnień ma znaczenie przede wszystkim dlatego, że ogranicza dostęp aplikacji do zasobów uznanych za wrażliwe. Ale samo istnienie uprawnienia nie oznacza jeszcze pełnego bezpieczeństwa. Uprawnienie mówi nam, że określona ścieżka dostępu została objęta kontrolą. Nie mówi jeszcze, czy dane mogą trafić do zewnętrznego odbiorcy inną drogą.

W praktyce to rozróżnienie jest fundamentalne. Jeśli aplikacja nie ma określonego uprawnienia, nie znaczy to automatycznie, że nie ma żadnego kontaktu z danymi. Publikacje o obejściach modelu uprawnień pokazują, że możliwe są zarówno kanały boczne, jak i kanały ukryte, w których jedna aplikacja pośredniczy w przekazaniu danych drugiej. Z punktu widzenia systemu wygląda to inaczej niż klasyczny odczyt z chronionego API, ale z punktu widzenia prywatności efekt jest podobny: dane opuszczają urządzenie mimo oczekiwanej ochrony.

W tej części wykładu „uprawnienie” jest więc tylko pierwszym punktem orientacyjnym. Musimy zaraz po nim zapytać, czy ochrona obejmuje także rzeczywisty przepływ informacji, czy tylko pojedynczą operację dostępu.

#slide 6
## layout
definition
## term
Zgoda uprzednia
## definition
Wyraźna, konkretna, świadoma i jednoznaczna zgoda uzyskana przed przekazaniem danych lub rozpoczęciem ich przetwarzania w danym celu.
## teleprompter:
W przypadku zgody najważniejsze jest słowo „uprzednia”. Zgoda nie może służyć do usprawiedliwiania transferu, który już nastąpił. Musi poprzedzać przetwarzanie, a nie je ratować post factum. Dlatego w badaniach nad zgodą na Androidzie kluczowe jest sprawdzenie, czy dane były przesyłane dopiero po aktywnej decyzji użytkownika, a nie „w tle”, zanim użytkownik zdążył w ogóle zareagować.

Drugie ważne słowo to „wyraźna”. Zgoda nie może być ukryta w ogólnych warunkach korzystania, w długim dokumencie polityki prywatności ani w domyślnie zaznaczonym polu. Badania dotyczące GDPR (General Data Protection Regulation, ogólne rozporządzenie o ochronie danych) pokazują, że w praktyce firmy i aplikacje mają problem nie tylko z samym uzyskaniem zgody, ale także z tym, jak tę zgodę dokumentują, interpretują i egzekwują. To jest właśnie różnica między legalną podstawą a formalnym kliknięciem.

W tym wykładzie zgoda będzie więc rozumiana bardzo rygorystycznie: jako mechanizm, który ma zmienić stan systemu zanim dane opuściły urządzenie. Jeśli tego nie robi, to nie spełnia swojej funkcji, nawet jeśli użytkownik widział ekran z przyciskiem.

#slide 7
## layout
bullet
## slide title
Dialog zgody
## bullets
- dialog musi dawać realny wybór
- odmowa musi być możliwa bez ukrytego kosztu
- wybór musi być zrozumiały w kontekście danych i celu
- styl interfejsu nie może zastępować decyzji
## teleprompter:
Samo pokazanie dialogu nie rozwiązuje problemu. Dialog zgody jest użyteczny tylko wtedy, gdy spełnia kilka warunków naraz. Po pierwsze, musi istnieć realny wybór. To znaczy, że użytkownik musi mieć możliwość odmowy bez sztucznego karania go za odmowę. Po drugie, odmowa musi faktycznie zmieniać zachowanie aplikacji. Jeśli kliknięcie „nie” jedynie odkłada wysyłkę danych albo tylko zmienia wygląd ekranu, a dane i tak wypływają, to dialog jest pozorny.

Po trzecie, użytkownik musi rozumieć, czego dotyczy zgoda. To nie może być ogólnikowa formuła typu „zgadzam się na przetwarzanie”. Musi być jasne, jakie dane mają zostać wysłane, do kogo i w jakim celu. Po czwarte, sam styl interfejsu nie może służyć do wymuszania jednej odpowiedzi. Jeśli przycisk akceptacji jest wielki, kolorowy i jednoznaczny, a odmowa ukryta, nieczytelna albo wymaga nadmiarowej liczby kroków, to interfejs przestaje wspierać decyzję, a zaczyna ją sterować.

Właśnie dlatego badania nad dialogami zgody nie kończą się na pytaniu „czy dialog istnieje”. One pytają: czy dialog daje wybór, czy odmowa działa, i czy forma dialogu nie wypacza sensu zgody. To jest kluczowe, bo w praktyce bardzo często to właśnie warstwa interfejsu decyduje o tym, czy mechanizm prawny jest rzeczywisty, czy tylko deklaratywny.

#slide 8
## layout
bullet
## slide title
Jak bada się obejścia
## bullets
- analiza dynamiczna: co aplikacja robi w runtime
- analiza statyczna: co wynika z kodu i konfiguracji
- analiza hybrydowa: jak połączyć oba widoki
- klasyfikacja prawna: kto otrzymuje dane i na jakiej podstawie
## teleprompter:
Badania użyte w tym wykładzie są interesujące nie tylko przez wyniki, ale także przez metodę. Sama analiza kodu nie wystarcza, bo kod może być obfuskowany, może korzystać z bibliotek zewnętrznych, może używać refleksji albo warunków środowiskowych, które zmieniają faktyczne zachowanie. Sama analiza runtime też nie wystarcza, bo aplikacja może nie uruchomić wszystkich ścieżek podczas testu, a część logiki może być aktywowana dopiero w określonym stanie lub po dłuższym czasie działania.

Dlatego w publikacjach pojawia się podejście hybrydowe. Najpierw obserwuje się zachowanie aplikacji w kontrolowanym środowisku. Potem konfrontuje się te obserwacje z kodem i konfiguracją, żeby ustalić, skąd dokładnie bierze się dane zachowanie. W jednym z badań zastosowano nawet triadę: analiza dynamiczna, analiza statyczna i interpretacja prawna odbiorcy danych. To pozwala przejść od sygnału technicznego do wniosku, czy dany transfer naprawdę narusza wymóg wcześniejszej zgody.

W praktyce to podejście jest dużo silniejsze niż pojedyncza technika. Dynamiczna analiza pokazuje fakt. Statyczna analiza pokazuje możliwość. Klasyfikacja prawna mówi, czy ten fakt lub ta możliwość ma znaczenie regulacyjne. Bez tej triady łatwo pomylić błąd implementacyjny z faktycznym naruszeniem albo odwrotnie.

#slide 9
## layout
bullet
## slide title
Skala problemu
## bullets
- 88 113 aplikacji w badaniu obejść modelu uprawnień
- 86 163 aplikacje w badaniu wcześniejszej zgody
- 3 006 aplikacji Android i 1 773 aplikacje iOS w badaniu dialogów
- 24 838 aplikacji z transferem do controllerów bez uprzedniej zgody
## teleprompter:
W tych badaniach najważniejsza nie jest tylko sama technika wykrycia, ale skala. Jedno naruszenie można zignorować jako przypadek. Dziesiątki tysięcy naruszeń pokazują, że problem jest systemowy. W badaniu dotyczącym obejść modelu uprawnień przeanalizowano 88 113 aplikacji i 252 864 ich wersje. W badaniu dotyczącym wcześniejszej zgody przeanalizowano 86 163 aplikacje i wykazano, że 24 838 z nich przekazywało dane osobowe do podmiotów działających jako controllerzy bez uprzedniej zgody użytkownika. W badaniu dialogów zgody przeanalizowano 3 006 aplikacji Android i 1 773 aplikacje iOS, a jedynie 11,9 procent wszystkich badanych aplikacji dawało użytkownikowi jakąkolwiek akcjonalną możliwość wyboru.

Te liczby mają znaczenie, bo pokazują, że nie chodzi o pojedynczą wadliwą aplikację. Chodzi o wzorzec zachowania, który powtarza się w dużej części ekosystemu. Jeśli problem pojawia się w dziesiątkach tysięcy aplikacji, to nie jest już anomalia na poziomie produktu. To jest cecha sposobu, w jaki aplikacje są projektowane, integrowane z bibliotekami zewnętrznymi i kierowane na rynek.

Na tym etapie wykładu dobrze jest zauważyć, że skala sama w sobie nie rozwiązuje interpretacji, ale bez skali nie da się odróżnić incydentu od klasy zjawiska. To dlatego później będziemy tak mocno wracać do połączenia pomiaru, klasyfikacji i interpretacji.

#slide 10
## layout
bullet
## slide title
Jak czytać wyniki
## bullets
- wynik techniczny nie jest jeszcze oceną prawną
- brak dialogu nie dowodzi automatycznie zgodności lub niezgodności
- jedno API nie opisuje całego przepływu danych
- liczba aplikacji nie mówi jeszcze, gdzie dokładnie leży błąd
## teleprompter:
Wykład ma też nauczyć czytania wyników. To bardzo ważne, bo dane z badań łatwo można źle zinterpretować. Sam wynik techniczny mówi tylko tyle, że w określonym środowisku i przy określonym zestawie testów zaszło pewne zachowanie. Aby przekształcić go w wniosek o prywatności, trzeba jeszcze odpowiedzieć na pytanie, kto otrzymał dane, na jakiej podstawie i czy użytkownik miał realną możliwość zablokowania transferu.

Tak samo brak dialogu zgody nie wystarcza jako dowód pełnej zgodności lub pełnej niezgodności. Może oznaczać, że aplikacja nie wykonuje żadnego transferu wymagającego uprzedniej zgody. Może też oznaczać, że transfer ukryto gdzie indziej, a sam dialog po prostu nie jest potrzebny z perspektywy implementacji, choć może być potrzebny z perspektywy prawa. Trzeba więc zawsze rozdzielić warstwę obserwacji od warstwy interpretacji.

To samo dotyczy liczb. Liczba aplikacji z wykrytym problemem mówi o skali, ale nie mówi jeszcze, czy problem wynika z błędu biblioteki, z decyzji developera, z konfiguracji domyślnej czy z polityki całej platformy. Dlatego w dalszej części wykładu nie będziemy traktować żadnej liczby jako zakończenia analizy. Każda liczba ma być początkiem pytania o mechanizm.

#slide 11
## layout
bullet
## slide title
Granice wniosków
## bullets
- pomiar nie naprawia systemu
- deklaracja nie zastępuje egzekwowania
- wybór użytkownika nie działa bez skutku operacyjnego
- polityka bez testu pozostaje opisem
## teleprompter:
Ten wykład ma jeszcze jedną ważną funkcję: ma pokazać granice tego, co można udowodnić samą obserwacją. Pomiar może wykazać zjawisko, ale nie naprawia systemu. Deklaracja może opisać, co powinno się dziać, ale nie wymusza zachowania. Wybór użytkownika ma wartość tylko wtedy, gdy system reaguje na niego w sposób operacyjny. A polityka bezpieczeństwa bez testu i bez mechanizmu wymuszania pozostaje tekstem, nie zabezpieczeniem.

To właśnie dlatego kolejne sekcje tego wykładu są tak różne: jedna sprawdza obejścia modelu uprawnień, druga sprawdza zgodę i przepływ do podmiotów trzecich, trzecia sprawdza jakość dialogów zgody, a kolejne pokazują, że równie ważne są wejście danych, dostępność i egzekwowanie polityk wewnątrz aplikacji. Wspólnym mianownikiem jest to, że nie wystarczy opisać bezpieczeństwa. Trzeba jeszcze pokazać, gdzie ono jest wymuszane.

Granica wniosku jest więc prosta: jeśli coś ma chronić prywatność, musi być widoczne w danych, widoczne w zachowaniu i widoczne w tym, jak system reaguje na decyzję użytkownika. Bez tego zostaje nam tylko deklaracja.

#slide 12
## layout
title
## slide title
Teza wspólna
## subtitle
Prywatność działa tylko wtedy, gdy reguła, interfejs i egzekwowanie prowadzą do tego samego skutku
## teleprompter:
To jest zdanie, do którego będziemy wracać przez cały wykład. Jeśli reguła techniczna mówi jedno, interfejs pokazuje drugie, a egzekwowanie robi trzecie, to system jest niespójny i prędzej czy później zawiedzie. Jeśli uprawnienie istnieje, ale nie obejmuje całego przepływu danych, ochrona jest niepełna. Jeśli zgoda istnieje, ale nie jest uprzednia albo nie daje realnego wyboru, ochrona jest pozorna. Jeśli polityka istnieje, ale nie ma mechanizmu, który sprawdza jej wykonanie, to mamy opis zamiast zabezpieczenia.

W tym sensie cały wykład jest opowieścią o zgodności między trzema poziomami: technicznym, prawnym i operacyjnym. To nie jest wykład o jednym „magicznym” mechanizmie, który rozwiązuje problem prywatności. To jest wykład o tym, że prywatność trzeba projektować jako system, w którym sygnał, decyzja i skutek są ze sobą zsynchronizowane. Gdy synchronizacji nie ma, użytkownik widzi jedynie pozór kontroli.

Od tego miejsca przechodzimy do dalszych sekcji, które będą już sprawdzały konkretne klasy zjawisk: gdzie dokładnie model uprawnień jest obchodzony, jak wyglądają naruszenia zgody, jak mierzyć dialogi oraz jak system może egzekwować reguły nie tylko w teorii, ale i w praktyce. Ten wstęp ma więc tylko jedno zadanie: ustawić wspólny model myślenia, zanim wejdziemy w szczegóły.
