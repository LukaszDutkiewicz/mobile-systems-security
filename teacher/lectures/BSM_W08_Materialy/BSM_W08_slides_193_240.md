#slide 193
## layout
definition
## slide title
Continuity overview
## subtitle
Co to jest
## term
Continuity overview
## definition
Apple's Continuity obejmuje Handoff, Universal Clipboard i Wi-Fi Password Sharing.
## teleprompter:
Continuity łączy Handoff, Universal Clipboard i Wi-Fi Password Sharing przez BLE, AWDL i Wi-Fi. Reverse engineering i packet capture z macOS pokazują, że te funkcje mają własne ścieżki discovery, transfer i auth, a ich formaty wiadomości potrafią ujawniać typ urządzenia, wersję systemu i stan aktywności. To nie jest jeden protokół, tylko zestaw powiązanych usług, które współdzielą zasięg, bliskość i część informacji o tożsamości.
#slide 194
## layout
bullet
## slide title
Continuity overview
## subtitle
Jak działa
## bullets
- Continuity overview: Prace o Continuity pokazują że Handoff Universal Clipboard…
- Continuity overview: Continuity w ekosystemie Apple to Handoff Universal Clipboard…
- Continuity overview: PrivateDrop jest odpowiedzią na te błędy bo przenosi…
## teleprompter:
Przebieg rozdziela się na discovery, transfer i state sync. BLE wykrywa sąsiednie urządzenia, AWDL daje niskopoziomowy kanał wymiany, a warstwa aplikacyjna przenosi aktywność, schowek albo dane logowania między urządzeniami. W praktyce jedna część protokołu reklamuje obecność, druga wybiera partnera, a trzecia już przenosi właściwy stan.
#slide 195
## layout
bullet
## slide title
Continuity overview
## subtitle
Jak pęka
## bullets
- Continuity overview: Badania wskazują na leakage of identifying information trackability…
- Continuity overview: Prace o Continuity pokazują że Handoff Universal Clipboard…
- Continuity overview: Continuity w ekosystemie Apple to Handoff Universal Clipboard…
## teleprompter:
Punkt pęknięcia jest prosty: identyfikatory i metadane wciąż pojawiają się w ruchu, więc pasywny obserwator może powiązać urządzenia, aktywność i stan systemu. Badania pokazują także spoofing, relay i DoS na discovery oraz transport. Samo radio nie musi zostać złamane; wystarczy, że ktoś odczyta wzorzec ogłoszeń i dopasuje go do konkretnego sprzętu.
#slide 196
## layout
bullet
## slide title
Continuity overview
## subtitle
Jak się bronić
## bullets
- Continuity overview: PrivateDrop jest odpowiedzią na te błędy bo przenosi…
- Continuity overview: Prace o Continuity pokazują że Handoff Universal Clipboard…
- Continuity overview: Badania wskazują na leakage of identifying information trackability…
## teleprompter:
Obrona w tej rodzinie polega na ograniczeniu tego, co trafia do discovery, i na przeniesieniu weryfikacji kontaktu do PSI. PrivateDrop pokazuje, że można zredukować wyciek identyfikatorów bez rozwalania czasu odpowiedzi. Warstwa obrony nie dotyczy tylko samego porównania kontaktów, ale też tego, co w ogóle trafia na antenę przed porównaniem.
#slide 197
## layout
definition
## slide title
Handoff discovery
## subtitle
Co to jest
## term
Handoff discovery
## definition
Handoff zaczyna się od BLE discovery i przenosi activity state w stacku Continuity.
## teleprompter:
Handoff startuje od BLE discovery: urządzenia wymieniają sygnały bliskości i reklamują bieżącą aktywność, którą można przejąć na drugim urządzeniu. W praktyce to nie jest zwykły transfer pliku, tylko przeniesienie stanu pracy, które może obejmować aktualną kartę, edytowany dokument albo bieżącą sesję aplikacji.
#slide 198
## layout
bullet
## slide title
Handoff discovery
## subtitle
Jak działa
## bullets
- Handoff discovery: Prace o Continuity pokazują że Handoff Universal Clipboard…
- Handoff discovery: Continuity w ekosystemie Apple to Handoff Universal Clipboard…
- Handoff discovery: PrivateDrop jest odpowiedzią na te błędy bo przenosi…
## teleprompter:
Discovery opiera się na krótkich ogłoszeniach BLE i na stanie aktywności, który widzi druga strona. Kiedy urządzenie jest w zasięgu, druga maszyna może podjąć aktywność bez pełnego ręcznego parowania. To działa szybko, ale też zostawia obserwowalny ślad bliskości i aktualnego kontekstu pracy.
#slide 199
## layout
bullet
## slide title
Handoff discovery
## subtitle
Jak pęka
## bullets
- Handoff discovery: Badania wskazują na leakage of identifying information trackability…
- Handoff discovery: Prace o Continuity pokazują że Handoff Universal Clipboard…
- Handoff discovery: Continuity w ekosystemie Apple to Handoff Universal Clipboard…
## teleprompter:
Handoff pęka tam, gdzie format ogłoszenia zdradza więcej niż powinien: typ urządzenia, wersję OS albo wzorzec zachowania. Pasywny słuchacz dostaje korelację między urządzeniami bez potrzeby wejścia w sesję, a z kilku reklam potrafi złożyć dłuższą historię niż pojedyncze połączenie.
#slide 200
## layout
bullet
## slide title
Handoff discovery
## subtitle
Jak się bronić
## bullets
- Handoff discovery: PrivateDrop jest odpowiedzią na te błędy bo przenosi…
- Handoff discovery: Prace o Continuity pokazują że Handoff Universal Clipboard…
- Handoff discovery: Badania wskazują na leakage of identifying information trackability…
## teleprompter:
Bezpieczna wersja Handoff wymaga zmniejszenia ujawnianych metadanych i kontroli, kto może interpretować discovery. Sam BLE nie jest problemem; problemem jest to, co wychodzi poza niezbędne minimum. Jeśli reklama niesie identyfikatory albo wzorce użycia, trzeba je ograniczyć zanim stan trafi do drugiego urządzenia.
#slide 201
## layout
definition
## slide title
AirDrop discovery
## subtitle
Co to jest
## term
AirDrop discovery
## definition
AirDrop używa discovery, authentication i transferu na bazie BLE, AWDL i Wi-Fi.
## teleprompter:
AirDrop używa BLE, AWDL i Wi-Fi: BLE znajduje sąsiadów, AWDL buduje szybki kanał lokalny, a Wi-Fi przenosi właściwy transfer. To trzy różne warstwy, które razem tworzą jedną ścieżkę wymiany, przy czym każda warstwa widzi inny fragment tożsamości i kontekstu.
#slide 202
## layout
bullet
## slide title
AirDrop discovery
## subtitle
Jak działa
## bullets
- AirDrop discovery: Prace o Continuity pokazują że Handoff Universal Clipboard…
- AirDrop discovery: Continuity w ekosystemie Apple to Handoff Universal Clipboard…
- AirDrop discovery: PrivateDrop jest odpowiedzią na te błędy bo przenosi…
## teleprompter:
Po discovery następuje uwierzytelnienie i decyzja, czy transfer w ogóle rusza. Jeśli contact discovery jest zrobione źle, sam etap wyboru odbiorcy może ujawnić identyfikatory kontaktów. W praktyce problem zaczyna się jeszcze przed wysłaniem treści, bo sama lista potencjalnych odbiorców bywa już cenną informacją.
#slide 203
## layout
bullet
## slide title
AirDrop discovery
## subtitle
Jak pęka
## bullets
- AirDrop discovery: Badania wskazują na leakage of identifying information trackability…
- AirDrop discovery: Prace o Continuity pokazują że Handoff Universal Clipboard…
- AirDrop discovery: Continuity w ekosystemie Apple to Handoff Universal Clipboard…
## teleprompter:
Błędy w AirDrop nie muszą wyglądać jak klasyczny exploit. Wystarczy, że kontakt lub urządzenie zostanie ujawnione przez odpowiedź discovery, albo że obserwator zobaczy wzorzec prób i odrzuceń. To jest typowy przypadek, w którym prywatność łamie się na metadanych, nie na zawartości pliku.
#slide 204
## layout
bullet
## slide title
AirDrop discovery
## subtitle
Jak się bronić
## bullets
- AirDrop discovery: PrivateDrop jest odpowiedzią na te błędy bo przenosi…
- AirDrop discovery: Prace o Continuity pokazują że Handoff Universal Clipboard…
- AirDrop discovery: Badania wskazują na leakage of identifying information trackability…
## teleprompter:
PrivateDrop pokazuje, jak usunąć kontakt discovery z jawnego kanału. Mutual authentication idzie przez PSI, a celem jest ograniczenie przecieku identyfikatorów przy zachowaniu sensownej opóźnionosci. W praktyce chodzi o to, żeby urządzenia porozumiały się co do wspólnego kontaktu bez pokazywania sobie pełnych list adresów.
#slide 205
## layout
definition
## slide title
PrivateDrop
## subtitle
Co to jest
## term
PrivateDrop
## definition
PrivateDrop zastępuje leaked contact checks mechanizmem PSI, żeby nie ujawniać phone number ani email.
## teleprompter:
PrivateDrop zamienia kruche contact checks na PSI, żeby nie ujawniać telefonu ani maila. To inny model niż zwykły broadcast: porównanie zbiorów odbywa się bez wypisywania kontaktów na zewnątrz, więc obserwator nie dostaje gotowego katalogu osób w pobliżu.
#slide 206
## layout
bullet
## slide title
PrivateDrop
## subtitle
Jak działa
## bullets
- PrivateDrop: Prace o Continuity pokazują że Handoff Universal Clipboard…
- PrivateDrop: Continuity w ekosystemie Apple to Handoff Universal Clipboard…
- PrivateDrop: PrivateDrop jest odpowiedzią na te błędy bo przenosi…
## teleprompter:
Przebieg PrivateDrop ma trzy etapy: ukryte porównanie kontaktów, wybór zgodnego partnera i dopiero potem transfer. W badaniach pokazano, że da się utrzymać odpowiedź poniżej jednej sekundy, więc prywatność nie musi kosztować zauważalnego opóźnienia.
#slide 207
## layout
bullet
## slide title
PrivateDrop
## subtitle
Jak pęka
## bullets
- PrivateDrop: Badania wskazują na leakage of identifying information trackability…
- PrivateDrop: Prace o Continuity pokazują że Handoff Universal Clipboard…
- PrivateDrop: Continuity w ekosystemie Apple to Handoff Universal Clipboard…
## teleprompter:
Atak na PrivateDrop wraca do tego samego miejsca, co w AirDrop: do discovery i kontaktów. Jeżeli którakolwiek odpowiedź ujawnia za dużo, prywatność znika mimo użycia PSI w innym kroku. Wystarczy jeden zbyt gadatliwy komunikat, żeby cały mechanizm przestał być prywatny.
#slide 208
## layout
bullet
## slide title
PrivateDrop
## subtitle
Jak się bronić
## bullets
- PrivateDrop: PrivateDrop jest odpowiedzią na te błędy bo przenosi…
- PrivateDrop: Prace o Continuity pokazują że Handoff Universal Clipboard…
- PrivateDrop: Badania wskazują na leakage of identifying information trackability…
## teleprompter:
Obrona wymaga kontrolowania, co trafia do discovery, i ograniczenia jawnych identyfikatorów do absolutnego minimum. Jeśli analiza pakietów nadal pokazuje identyfikatory albo wzorce obecności, mechanizm trzeba poprawić. PSI nie naprawi wszystkiego, jeśli druga warstwa nadal emituje zbyt dużo metadanych.
#slide 209
## layout
definition
## slide title
AWDL and BLE
## subtitle
Co to jest
## term
AWDL and BLE
## definition
AWDL i BLE niosą niskopoziomowy ruch discovery oraz widoczny dla użytkownika stan Continuity.
## teleprompter:
AWDL i BLE to kanały, na których widać lokalny ruch Continuity zanim zacznie się właściwy transfer. BLE daje wykrycie, AWDL daje szybkie połączenie w pobliżu, a razem ujawniają sporo o ruchu urządzeń. W przeciwieństwie do zwykłego internetu, tutaj sama obecność w zasięgu jest już informacją.
#slide 210
## layout
bullet
## slide title
AWDL and BLE
## subtitle
Jak działa
## bullets
- AWDL and BLE: Prace o Continuity pokazują że Handoff Universal Clipboard…
- AWDL and BLE: Continuity w ekosystemie Apple to Handoff Universal Clipboard…
- AWDL and BLE: PrivateDrop jest odpowiedzią na te błędy bo przenosi…
## teleprompter:
W praktyce oba kanały niosą reklamę obecności i dane pomocnicze dla discovery. To znaczy, że ktoś z dostępem radiowym może złożyć obraz pobliskich urządzeń nawet bez udziału aplikacji. Nie trzeba przechwycić sesji, żeby zrozumieć, kto jest w pobliżu i kiedy aktywuje usługę.
#slide 211
## layout
bullet
## slide title
AWDL and BLE
## subtitle
Jak pęka
## bullets
- AWDL and BLE: Badania wskazują na leakage of identifying information trackability…
- AWDL and BLE: Prace o Continuity pokazują że Handoff Universal Clipboard…
- AWDL and BLE: Continuity w ekosystemie Apple to Handoff Universal Clipboard…
## teleprompter:
Punkt pęknięcia to korelacja pakietów z konkretnymi urządzeniami i zachowaniami. W samych ramkach da się wyciągnąć identyfikatory, wersje i ślady aktywności. Jeśli kilka komunikatów powtarza te same cechy, obserwator może śledzić urządzenie w czasie bez łamania żadnej warstwy szyfrowania.
#slide 212
## layout
bullet
## slide title
AWDL and BLE
## subtitle
Jak się bronić
## bullets
- AWDL and BLE: PrivateDrop jest odpowiedzią na te błędy bo przenosi…
- AWDL and BLE: Prace o Continuity pokazują że Handoff Universal Clipboard…
- AWDL and BLE: Badania wskazują na leakage of identifying information trackability…
## teleprompter:
Ochrona polega na ograniczeniu publicznych metadanych i na przeniesieniu krytycznej weryfikacji do kanału, który nie zdradza identyfikatorów wprost. PSI rozwiązuje tylko część problemu; druga część to dyscyplina transportu, czyli to, co wypływa w ogłoszeniach, kolejności pakietów i błędach odpowiedzi.
#slide 213
## layout
definition
## slide title
Cross-device identity
## subtitle
Co to jest
## term
Cross-device identity
## definition
Messagi Continuity mogą ujawniać typ urządzenia, wersję OS i zachowanie pasywnemu obserwatorowi.
## teleprompter:
Cross-device identity w Continuity ujawnia typ urządzenia, wersję systemu i wzorce użycia pasywnemu obserwatorowi. To nie jest tylko pairing, ale ciągły sygnał o obecności i stanie ekosystemu. Z perspektywy analizy radiowej to stałe źródło metadanych, które można korelować z kolejnymi reklamami.
#slide 214
## layout
bullet
## slide title
Cross-device identity
## subtitle
Jak działa
## bullets
- Cross-device identity: Prace o Continuity pokazują że Handoff Universal Clipboard…
- Cross-device identity: Continuity w ekosystemie Apple to Handoff Universal Clipboard…
- Cross-device identity: PrivateDrop jest odpowiedzią na te błędy bo przenosi…
## teleprompter:
Mechanika jest prosta: urządzenia reklamują siebie i swoją aktywność, a druga strona podejmuje decyzję o przejęciu stanu. Właśnie przez to ruch nie wygląda jak zwykły, jednokierunkowy transfer. Zamiast jednego pakietu masz serię reklam i odpowiedzi, z których każda mówi coś o urządzeniu.
#slide 215
## layout
bullet
## slide title
Cross-device identity
## subtitle
Jak pęka
## bullets
- Cross-device identity: Badania wskazują na leakage of identifying information trackability…
- Cross-device identity: Prace o Continuity pokazują że Handoff Universal Clipboard…
- Cross-device identity: Continuity w ekosystemie Apple to Handoff Universal Clipboard…
## teleprompter:
Pęknięcie wynika z linkability. Jeśli te same metadane powracają w kolejnych reklamach, można śledzić urządzenie i jego właściciela w czasie. Wystarczy kilka obserwacji, żeby z anonimowej obecności zrobić rozpoznawalny wzorzec.
#slide 216
## layout
bullet
## slide title
Cross-device identity
## subtitle
Jak się bronić
## bullets
- Cross-device identity: PrivateDrop jest odpowiedzią na te błędy bo przenosi…
- Cross-device identity: Prace o Continuity pokazują że Handoff Universal Clipboard…
- Cross-device identity: Badania wskazują na leakage of identifying information trackability…
## teleprompter:
Obrona zaczyna się od redukcji reklamowanych identyfikatorów i od oddzielenia discovery od pełnej tożsamości użytkownika. PSI pomaga tylko wtedy, gdy reszta warstwy też nie zdradza za dużo. Jeśli reklama nadal zawiera zbyt wiele danych, nawet najlepsze porównanie kontaktów nie wystarczy.
#slide 217
## layout
definition
## slide title
Spoof relay downgrade
## subtitle
Co to jest
## term
Spoof relay downgrade
## definition
Atakujący może spoofować, relayować albo downgrade'ować discovery i authentication.
## teleprompter:
Spoofing, relay i downgrade działają, bo discovery i authentication są rozdzielone. Atakujący może podmienić reklamę, przekazać ją dalej albo wymusić słabszy wariant wymiany. W praktyce chodzi o przejęcie pierwszego kroku tak, żeby reszta protokołu uwierzyła w zły punkt startowy.
#slide 218
## layout
bullet
## slide title
Spoof relay downgrade
## subtitle
Jak działa
## bullets
- Spoof relay downgrade: Prace o Continuity pokazują że Handoff Universal Clipboard…
- Spoof relay downgrade: Continuity w ekosystemie Apple to Handoff Universal Clipboard…
- Spoof relay downgrade: PrivateDrop jest odpowiedzią na te błędy bo przenosi…
## teleprompter:
Mechanicznie to wygląda jak przejęcie pierwszej reklamy, przepuszczenie jej przez pośrednika i wymuszenie gorszej ścieżki dalszej komunikacji. Wtedy druga strona ufa nie temu partnerowi, który powinna. Relay działa tu szczególnie dobrze, jeśli system nie ma silnego związania reklamy z właściwym źródłem.
#slide 219
## layout
bullet
## slide title
Spoof relay downgrade
## subtitle
Jak pęka
## bullets
- Spoof relay downgrade: Badania wskazują na leakage of identifying information trackability…
- Spoof relay downgrade: Prace o Continuity pokazują że Handoff Universal Clipboard…
- Spoof relay downgrade: Continuity w ekosystemie Apple to Handoff Universal Clipboard…
## teleprompter:
Pęknięcie daje pasywny odczyt albo aktywne przekierowanie ruchu. Jeśli downgrade schodzi na słabszą metodę, bezpieczeństwo transferu spada bez widocznego alarmu. To klasyczny przypadek, gdzie skuteczność protokołu zależy od tego, czy odrzuca on zbyt słabe ścieżki zamiast je akceptować.
#slide 220
## layout
bullet
## slide title
Spoof relay downgrade
## subtitle
Jak się bronić
## bullets
- Spoof relay downgrade: PrivateDrop jest odpowiedzią na te błędy bo przenosi…
- Spoof relay downgrade: Prace o Continuity pokazują że Handoff Universal Clipboard…
- Spoof relay downgrade: Badania wskazują na leakage of identifying information trackability…
## teleprompter:
Obrona to nie tylko PSI, ale też twarde odrzucanie relayed i downgraded ścieżek. Jeśli format wiadomości albo wybór transportu zdradza za dużo, trzeba to odciąć zanim zacznie się transfer. Silna ścieżka bezpieczeństwa nie może zależeć od „ładniejszej” odpowiedzi, tylko od autentycznego związania partnera z ogłoszeniem.
#slide 221
## layout
definition
## slide title
Transport and state machine
## subtitle
Co to jest
## term
Transport and state machine
## definition
Structured analysis wymaga obserwacji całego state machine na różnych vantage points macOS.
## teleprompter:
Badanie Continuity wymaga patrzenia na cały state machine, a nie na pojedynczy pakiet. Discovery, auth i transfer mają różne punkty obserwacji, więc jeden capture nie wystarcza. Dopiero porównanie kilku punktów w czasie pokazuje, czy protokół przechodzi przez poprawne stany.
#slide 222
## layout
bullet
## slide title
Transport and state machine
## subtitle
Jak działa
## bullets
- Transport and state machine: Prace o Continuity pokazują że Handoff Universal Clipboard…
- Transport and state machine: Continuity w ekosystemie Apple to Handoff Universal Clipboard…
- Transport and state machine: PrivateDrop jest odpowiedzią na te błędy bo przenosi…
## teleprompter:
Kolejność jest zawsze ważna: najpierw reklama i discovery, potem weryfikacja, potem właściwy transfer. Jeśli jeden etap przeskoczy poprzedni, stany zaczynają się rozjeżdżać i packet trace przestaje odpowiadać temu, co system uważa za legalny przebieg.
#slide 223
## layout
bullet
## slide title
Transport and state machine
## subtitle
Jak pęka
## bullets
- Transport and state machine: Badania wskazują na leakage of identifying information trackability…
- Transport and state machine: Prace o Continuity pokazują że Handoff Universal Clipboard…
- Transport and state machine: Continuity w ekosystemie Apple to Handoff Universal Clipboard…
## teleprompter:
Pęknięcia najlepiej widać, gdy korelujesz ruch z momentem przełączania stanu. Wtedy da się zobaczyć, czy urządzenie ujawnia zbyt wiele już na etapie identyfikacji. Samo spojrzenie na pojedyncze ramki zwykle ukrywa szerszy wzorzec błędu.
#slide 224
## layout
bullet
## slide title
Transport and state machine
## subtitle
Jak się bronić
## bullets
- Transport and state machine: PrivateDrop jest odpowiedzią na te błędy bo przenosi…
- Transport and state machine: Prace o Continuity pokazują że Handoff Universal Clipboard…
- Transport and state machine: Badania wskazują na leakage of identifying information trackability…
## teleprompter:
Obrona wymaga testów, które obserwują każdy stan i każdą zmianę kanału. Bez tego nie wiadomo, czy format wiadomości jest bezpieczny, czy tylko wygląda neutralnie w jednym capture. W praktyce trzeba powtarzać test przy różnych odległościach, stanach urządzeń i kierunkach ruchu.
#slide 225
## layout
definition
## slide title
Packet analysis
## subtitle
Co to jest
## term
Packet analysis
## definition
Packet captures pokazują, które pola są szyfrowane, a które metadata lecą jawnie.
## teleprompter:
Packet capture pokazuje, które pola są jawne, a które chronione. W Continuity to ważne, bo właśnie z metadanych da się wyciągnąć najwięcej informacji o urządzeniu i aktywności. Dla atakującego cenne są też różnice w długości ramek, częstotliwości oraz powtarzalności odpowiedzi.
#slide 226
## layout
bullet
## slide title
Packet analysis
## subtitle
Jak działa
## bullets
- Packet analysis: Prace o Continuity pokazują że Handoff Universal Clipboard…
- Packet analysis: Continuity w ekosystemie Apple to Handoff Universal Clipboard…
- Packet analysis: PrivateDrop jest odpowiedzią na te błędy bo przenosi…
## teleprompter:
Przebieg analizy zaczyna się od capture, potem idzie przez rekonstrukcję state machine i porównanie ramek z zachowaniem urządzeń. Reverse engineering nie jest dodatkiem, tylko sposobem zrozumienia ukrytych przejść, bo bez niego nie wiadomo, która odpowiedź należy do którego stanu.
#slide 227
## layout
bullet
## slide title
Packet analysis
## subtitle
Jak pęka
## bullets
- Packet analysis: Badania wskazują na leakage of identifying information trackability…
- Packet analysis: Prace o Continuity pokazują że Handoff Universal Clipboard…
- Packet analysis: Continuity w ekosystemie Apple to Handoff Universal Clipboard…
## teleprompter:
Atak wykorzystuje te same pakiety, ale patrzy na ich powtarzalność, korelację i niejawne identyfikatory. To pozwala śledzić zachowanie bez łamania szyfrowania. Jeśli te cechy są stabilne, pakiety zaczynają pełnić rolę odcisku palca urządzenia.
#slide 228
## layout
bullet
## slide title
Packet analysis
## subtitle
Jak się bronić
## bullets
- Packet analysis: PrivateDrop jest odpowiedzią na te błędy bo przenosi…
- Packet analysis: Prace o Continuity pokazują że Handoff Universal Clipboard…
- Packet analysis: Badania wskazują na leakage of identifying information trackability…
## teleprompter:
Obrona to ograniczenie jawnych metadanych i sprawdzanie, czy capture nadal nie daje wystarczająco dużo do korelacji. Jeśli tak, protokół trzeba odchudzić. Samo szyfrowanie payloadu nie pomaga, jeśli identyfikacja siedzi w nagłówku albo w rytmie odpowiedzi.
#slide 229
## layout
definition
## slide title
Mitigations
## subtitle
Co to jest
## term
Mitigations
## definition
PSI, większa ostrożność w contact discovery i twardsza kontrola widoczności ograniczają wyciek.
## teleprompter:
PSI i mocniejsza kontrola widoczności ograniczają wyciek, bo kontakt nie musi być wystawiany wprost. PrivateDrop jest właśnie przykładem takiej redukcji, bo usuwa jawne porównanie kontaktów z kanału discovery.
#slide 230
## layout
bullet
## slide title
Mitigations
## subtitle
Jak działa
## bullets
- Mitigations: Prace o Continuity pokazują że Handoff Universal Clipboard…
- Mitigations: Continuity w ekosystemie Apple to Handoff Universal Clipboard…
- Mitigations: PrivateDrop jest odpowiedzią na te błędy bo przenosi…
## teleprompter:
Przebieg obrony polega na porównaniu zbiorów bez ujawnienia członków zbioru. Dzięki temu discovery nie wypisuje kontaktów, tylko sprawdza zgodność. Z punktu widzenia użytkownika wygląda to jak zwykłe wykrycie, ale z punktu widzenia sieci nie ma listy kontaktów do przechwycenia.
#slide 231
## layout
bullet
## slide title
Mitigations
## subtitle
Jak pęka
## bullets
- Mitigations: Badania wskazują na leakage of identifying information trackability…
- Mitigations: Prace o Continuity pokazują że Handoff Universal Clipboard…
- Mitigations: Continuity w ekosystemie Apple to Handoff Universal Clipboard…
## teleprompter:
Pęknięcie wraca, gdy transport lub discovery zdradza więcej niż sam PSI. Wtedy prywatność wypada nie na etapie porównania, ale na warstwie pomocniczej. To właśnie tam najłatwiej pojawiają się błędy typu zbyt gadatliwa odpowiedź, zbyt długi czas albo zbyt stabilny wzorzec.
#slide 232
## layout
bullet
## slide title
Mitigations
## subtitle
Jak się bronić
## bullets
- Mitigations: PrivateDrop jest odpowiedzią na te błędy bo przenosi…
- Mitigations: Prace o Continuity pokazują że Handoff Universal Clipboard…
- Mitigations: Badania wskazują na leakage of identifying information trackability…
## teleprompter:
Obrona jest skuteczna dopiero wtedy, gdy testy potwierdzają brak jawnych identyfikatorów, dobry czas odpowiedzi i brak relayed ścieżek. Jeśli którykolwiek z tych warunków odpada, prywatność jest tylko częściowa i trzeba poprawić protokół.
#slide 233
## layout
definition
## slide title
Test matrix
## subtitle
Co to jest
## term
Test matrix
## definition
Dobry test matrix zmienia stan urządzenia, odległość i użyty transport.
## teleprompter:
Dobrze ustawiony test matrix zmienia stan urządzenia, odległość i transport, bo tylko wtedy widać, jak protokół zachowuje się w różnych warunkach radiowych.
#slide 234
## layout
bullet
## slide title
Test matrix
## subtitle
Jak działa
## bullets
- Test matrix: Prace o Continuity pokazują że Handoff Universal Clipboard…
- Test matrix: Continuity w ekosystemie Apple to Handoff Universal Clipboard…
- Test matrix: PrivateDrop jest odpowiedzią na te błędy bo przenosi…
## teleprompter:
Przebieg testów musi obejmować discovery, authentication i transfer w różnych konfiguracjach zasięgu. Jedno ustawienie pokazuje za mało.
#slide 235
## layout
bullet
## slide title
Test matrix
## subtitle
Jak pęka
## bullets
- Test matrix: Badania wskazują na leakage of identifying information trackability…
- Test matrix: Prace o Continuity pokazują że Handoff Universal Clipboard…
- Test matrix: Continuity w ekosystemie Apple to Handoff Universal Clipboard…
## teleprompter:
Pęknięcie pojawia się, gdy jeden wariant ustawienia wygląda dobrze, ale inny ujawnia identyfikatory albo relayed pakiety. Bez porównania warunków nie ma oceny bezpieczeństwa.
#slide 236
## layout
bullet
## slide title
Test matrix
## subtitle
Jak się bronić
## bullets
- Test matrix: PrivateDrop jest odpowiedzią na te błędy bo przenosi…
- Test matrix: Prace o Continuity pokazują że Handoff Universal Clipboard…
- Test matrix: Badania wskazują na leakage of identifying information trackability…
## teleprompter:
Obrona wymaga pokrycia całej macierzy: zasięg, liczba urządzeń, typ transportu, stan zaufania i stan kontaktów. Dopiero wtedy wynik jest coś wart.
#slide 237
## layout
definition
## slide title
Android comparison
## subtitle
Co to jest
## term
Android comparison
## definition
Android local-network policy daje użyteczny kontrast dla zawsze aktywnych kanałów continuity.
## teleprompter:
Android local-network policy daje kontrast: tam dostęp do sieci lokalnej jest kontrolowany i wprost opisany, więc łatwiej zobaczyć, czego brakuje w Always-On Continuity.
#slide 238
## layout
bullet
## slide title
Android comparison
## subtitle
Jak działa
## bullets
- Android comparison: Prace o Continuity pokazują że Handoff Universal Clipboard…
- Android comparison: Continuity w ekosystemie Apple to Handoff Universal Clipboard…
- Android comparison: PrivateDrop jest odpowiedzią na te błędy bo przenosi…
## teleprompter:
Przebieg Androida pokazuje podejście permission-first, a Continuity działa bardziej jak stały kanał discovery. To różnica w modelu zaufania, nie tylko w implementacji.
#slide 239
## layout
bullet
## slide title
Android comparison
## subtitle
Jak pęka
## bullets
- Android comparison: Badania wskazują na leakage of identifying information trackability…
- Android comparison: Prace o Continuity pokazują że Handoff Universal Clipboard…
- Android comparison: Continuity w ekosystemie Apple to Handoff Universal Clipboard…
## teleprompter:
Pęknięcie w Continuity polega na tym, że radio samo ujawnia obecność i wzorce użycia, bez osobnego runtime promptu. Androidowa polityka lokalnej sieci robi z tego twardy kontrast.
#slide 240
## layout
bullet
## slide title
Android comparison
## subtitle
Jak się bronić
## bullets
- Android comparison: PrivateDrop jest odpowiedzią na te błędy bo przenosi…
- Android comparison: Prace o Continuity pokazują że Handoff Universal Clipboard…
- Android comparison: Badania wskazują na leakage of identifying information trackability…
## teleprompter:
Obrona jest prostsza do nazwania: ograniczać discovery, redukować widoczne metadane i wymagać świadomego użycia kanału. Jeśli porównanie z Androidem coś wnosi, to właśnie tę różnicę między aktywną zgodą a ciągłą reklamą obecności.
