#slide 1
## layout
definition
## slide title
mDNS record anatomy
## subtitle
Co to jest
## term
mDNS record anatomy
## definition
mDNS ogłasza usługi w LAN przez rekordy PTR, SRV i TXT wysyłane na UDP 5353.
## teleprompter:
mDNS działa przez multicast DNS na UDP 5353 i ogłasza usługi przez rekordy PTR, SRV i TXT. Rekord PTR mówi, jaką nazwę usługi ma rozwiązać klient, SRV prowadzi do hosta i portu, a TXT niesie parę dodatkowych parametrów usługi. W praktyce ten sam wzorzec ujawnia nazwę urządzenia, typ usługi i adres, zanim aplikacja w ogóle wykona własne uwierzytelnienie.
W Android 16 lokalna sieć jest funkcją opt-in, żeby developerzy znaleźli zależności od implicit local network access. Android 17 ma ten model wymuszać dla nowych targetów, a sam dokument wymienia też typowe błędy socketów oraz NDK helper do sprawdzania, dlaczego ruch został zablokowany. To jest ważne, bo zwykły `INTERNET` nie odcina aplikacji od LAN.
W praktyce mDNS staje się źródłem fingerprintingu i enumeracji usług. Jeśli aplikacja przyjmuje rekord lokalny bez własnej walidacji, przeciwnik może podszyć się pod usługę, podmienić odpowiedź albo wymusić błędny routing. Odpowiedź obronna musi mówić wprost, które sockety mają prawo widzieć LAN, a które powinny dostać blokadę.

#slide 2
## layout
bullet
## slide title
mDNS record anatomy
## subtitle
Jak działa
## bullets
- Rekordy PTR, SRV i TXT
- Multicast na UDP 5353
- LAN widoczny zanim padnie auth
- Typ usługi i port
## teleprompter:
Najpierw mDNS wysyła zapytanie lub odpowiedź na multicast, a potem klient dostaje nazwę usługi, hostname, port i pola TXT. To nie jest zwykłe „odkrycie”, tylko zbudowanie mapy usług w otoczeniu zanim zacznie się jakakolwiek autoryzacja.
W Androidzie problem polega na tym, że zwykłe `INTERNET` nie zamyka dostępu do LAN. `RESTRICT_LOCAL_NETWORK` i późniejsze `ACCESS_LOCAL_NETWORK` służą właśnie do tego, żeby zobaczyć i potem wymusić, które sockety naprawdę mają prawo rozmawiać z mDNS i resztą lokalnych protokołów.
Jeśli aplikacja bierze lokalny rekord za prawdziwy, a nie sprawdza hosta, portu albo źródła odpowiedzi, to atakujący może wstawić własną usługę i podmienić ścieżkę komunikacji. Wtedy widać już nie tylko nazwę hosta, ale cały punkt zaczepienia dla dalszego ruchu.

#slide 3
## layout
bullet
## slide title
mDNS record anatomy
## subtitle
Jak pęka
## bullets
- Spoofing odpowiedzi
- Korelacja broadcastów
- Lokalny rekord bez walidacji
- Błędny host albo port
## teleprompter:
Atak zaczyna się od odpowiedzi udającej prawdziwy rekord mDNS. Jeśli klient nie sprawdza źródła, hosta i portu, to traktuje lokalną odpowiedź jak zaufaną i buduje na niej dalszą komunikację.
W takim scenariuszu przeciwnik nie potrzebuje przełamywać całego systemu. Wystarczy, że podstawi rekord z własnym hostname albo własnym portem i zmusi aplikację do połączenia z fałszywą usługą.
Na urządzeniu widać to jako błędny routing, timeout, albo połączenie do obcej usługi podszywającej się pod prawdziwą. Jeśli aplikacja używa NsdManager, błąd może wyglądać jak poprawne znalezienie usługi, a w rzeczywistości prowadzić do podstawionej odpowiedzi.

#slide 4
## layout
bullet
## slide title
mDNS record anatomy
## subtitle
Jak się bronić
## bullets
- RESTRICT_LOCAL_NETWORK w Android 16
- ACCESS_LOCAL_NETWORK w Android 17
- `android_getnetworkblockedreason`
- WebView i sockety
## teleprompter:
Obrona zaczyna się od rozdzielenia tego, co ma widzieć Internet, od tego, co ma widzieć LAN. Android 16 daje opt-in, żeby znaleźć zależności od lokalnej sieci, a Android 17 ma ten model wymuszać dla nowych targetów.
Jeśli aplikacja naprawdę potrzebuje discovery, trzeba to wyrazić wprost przez uprawnienie i przetestować reakcję na blokadę socketu. Jeśli potrzebuje tylko wyboru usługi przez system, to nie powinna dostawać szerokiego dostępu do całej podsieci.
NDK helper pokazuje, dlaczego ruch został zablokowany, a WebView przypomina, że stan dostępu może być dziedziczony po host app, więc sam manifest nie kończy tematu. Obrona jest poprawna dopiero wtedy, gdy zły przypadek faktycznie się wywraca, a dobry przechodzi bez obejścia blokady.

#slide 5
## layout
definition
## slide title
SSDP discovery
## subtitle
Co to jest
## term
SSDP discovery
## definition
SSDP wykrywa urządzenia przez M-SEARCH, NOTIFY i nagłówek LOCATION.
## teleprompter:
SSDP wykrywa urządzenia przez M-SEARCH, NOTIFY i nagłówek LOCATION.
mDNS, SSDP i link-local IPv6 pokazują, że sama obecność w LAN daje aplikacji bardzo dużo informacji o pobliskich usługach i urządzeniach. mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.
Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi. SSDP wykrywa urządzenia przez M-SEARCH, NOTIFY i nagłówek LOCATION. pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał.
LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK. Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation.

#slide 6
## layout
bullet
## slide title
SSDP discovery
## subtitle
Jak działa
## bullets
- M-SEARCH i NOTIFY
- Nagłówek LOCATION
- Odpowiedź bez weryfikacji
- Źródło usługi
## teleprompter:
SSDP zaczyna od broadcastu `M-SEARCH`, a urządzenie odpowiada zwykle przez nagłówek `LOCATION`, który wskazuje endpoint usługi. To jest prostszy mechanizm niż mDNS, ale problem bezpieczeństwa jest podobny: odpowiedź z sieci jest traktowana jako wskazówka, gdzie iść dalej.
Jeśli aplikacja przyjmuje `LOCATION` bez sprawdzenia, może połączyć się z podstawioną usługą albo z urządzeniem, które tylko udaje prawdziwy endpoint. W lokalnej sieci nie ma gwarancji, że odpowiedź przyszła od tego, kto powinien ją wysłać.
W praktyce SSDP służy do odkrywania sprzętu i usług, ale jednocześnie daje przeciwnikowi możliwość spoofingu i korelacji ruchu. Najłatwiej zobaczyć to wtedy, gdy aplikacja bazuje na odpowiedzi z sieci zamiast na własnym sprawdzeniu hosta i portu.

#slide 7
## layout
bullet
## slide title
SSDP discovery
## subtitle
Jak pęka
## bullets
- Broadcast `M-SEARCH`
- Nagłówek `LOCATION`
- Podstawiona usługa
- Lokalny endpoint
## teleprompter:
Atak na SSDP nie musi być skomplikowany. Wystarczy odpowiedź z poprawnym formatem i własnym `LOCATION`, żeby klient poszedł do fałszywego endpointu.
Jeżeli aplikacja traktuje lokalną odpowiedź jak dowód tożsamości usługi, to przegrana zaczyna się jeszcze przed autoryzacją. Przeciwnik nie łamie protokołu, tylko wykorzystuje to, że protokół zakłada zaufanie do sieci lokalnej.
W praktyce skutkiem jest połączenie z nieautoryzowanym urządzeniem, błędna identyfikacja sprzętu albo przynajmniej mylący wynik discovery, który potem trafia do UI lub do logiki połączenia.

#slide 8
## layout
bullet
## slide title
SSDP discovery
## subtitle
Jak się bronić
## bullets
- LAN i Internet osobno
- Wymuszony runtime permission
- NDK helper na blokadę
- WebView inheritance
## teleprompter:
Obrona w SSDP nie polega na „wyłączaniu discovery”, tylko na ograniczeniu tego, kto w ogóle może mówić do sieci lokalnej. Jeśli aplikacja potrzebuje tylko pojedynczego urządzenia, nie ma powodu, by dawała broad access do całej podsieci.
Android 16 i 17 pokazują, jak platforma przesuwa kontrolę z domyślnego dostępu do LAN na model explicite przyznanego uprawnienia. NDK helper pomaga wykryć blokadę, a WebView przypomina, że nie wolno zakładać, iż tylko kod Java zna stan uprawnienia.
Test obrony powinien sprawdzić zarówno blokadę socketu, jak i to, czy UI nie pokazuje usług znalezionych na podstawie fałszywego `LOCATION`.

#slide 9
## layout
definition
## slide title
IPv6 link-local
## subtitle
Co to jest
## term
IPv6 link-local
## definition
IPv6 link-local działa tylko na jednej karcie sieciowej i używa zakresu fe80::/10.
## teleprompter:
Adres link-local ma sens tylko na jednej karcie sieciowej i tylko w obrębie jednego segmentu. Zapis `fe80::/10` od razu mówi, że nie chodzi o routowalny Internet, tylko o lokalne sąsiedztwo sieciowe.
W praktyce ten adres jest używany tam, gdzie urządzenia chcą się znaleźć bez centralnego serwera. To jest wygodne dla discovery, ale nie daje żadnego dowodu tożsamości endpointu.
Jeżeli aplikacja traktuje sam lokalny adres jako zaufanie, to myli sąsiedztwo sieciowe z bezpieczeństwem. Dlatego obrona nie może opierać się na samym formacie adresu.

#slide 10
## layout
bullet
## slide title
IPv6 link-local
## subtitle
Jak działa
## bullets
- Adres tylko dla jednej karty
- Zakres `fe80::/10`
- Discovery bez zaufania
- Lokalność nie znaczy bezpieczeństwo
## teleprompter:
Link-local IPv6 nie przechodzi przez routery, więc nie da się go traktować jak zwykłego endpointu internetowego. Jeśli aplikacja spotyka adres `fe80::`, musi jeszcze wiedzieć, na którym interfejsie ma go użyć.
Bez scope ID adres bywa niejednoznaczny, a klient może wybrać złą kartę sieciową albo błędną trasę. To jest dokładnie ten moment, w którym sieć lokalna przestaje być wygodą, a staje się potencjalnym źródłem pomyłki.
Sama lokalność nie wystarcza do zaufania. Jeśli klient nie sprawdza hosta i interfejsu, to lokalny adres może prowadzić do fałszywego endpointu równie łatwo jak każdy inny rekord discovery.

#slide 11
## layout
bullet
## slide title
IPv6 link-local
## subtitle
Jak pęka
## bullets
- Fałszywy endpoint na LAN
- Zły wybór interfejsu
- Brak walidacji hosta
- Adres nie daje zaufania
## teleprompter:
Atak na link-local IPv6 polega na wykorzystaniu zaufania do lokalności. Klient widzi `fe80::` i zakłada, że to właściwa usługa, choć nie ma jeszcze potwierdzenia źródła.
Jeśli aplikacja nie sprawdza scope ID, hosta i odpowiedzi, może połączyć się z fałszywym endpointem na tej samej sieci albo na sąsiednim interfejsie. To nie jest problem routingu, tylko problem zaufania do adresu.
Efekt to mylące discovery albo ruch skierowany do podstawionego urządzenia. Sam format adresu nie daje bezpieczeństwa, a jedynie informację, gdzie szukać usługi.

#slide 12
## layout
bullet
## slide title
IPv6 link-local
## subtitle
Jak się bronić
## bullets
- Scope ID obowiązkowy
- `fe80::` to za mało
- Walidować host i port
- Test na złą kartę
## teleprompter:
Obrona link-local IPv6 zaczyna się od poprawnego wskazania interfejsu i scope ID. Bez tego klient nie wie, czy rozmawia z właściwym sąsiadem sieciowym.
Nie można zakładać, że sam adres `fe80::` wystarczy do zaufania. Trzeba jeszcze sprawdzić host, port i źródło odpowiedzi, bo tylko to oddziela lokalny parametr od prawdziwej usługi.
Test powinien wykazać, że zła karta sieciowa albo podstawiony endpoint nie przechodzą przez walidację. Jeśli to działa, wtedy lokalność jest tylko cechą transportu, a nie dowodem bezpieczeństwa.

#slide 13
## layout
definition
## slide title
Raw socket access
## subtitle
Co to jest
## term
Raw socket access
## definition
Surowe sockety pozwalają aplikacji próbować mDNS i SSDP nawet wtedy, gdy ma tylko INTERNET.
## teleprompter:
Raw socket pozwala aplikacji wysyłać i odbierać pakiety bez mediacji frameworka. To oznacza, że mDNS, SSDP albo inne lokalne protokoły discovery można implementować bez wyższego API.
To jest jednocześnie wygodne i niebezpieczne. Jeśli `INTERNET` zostaje jedynym wymaganym pozwoleniem, aplikacja może nadal próbować wchodzić do LAN, bo sama tworzy pakiety i sama je czyta.
W takim modelu to aplikacja decyduje, czy ufa odpowiedziom, czy tylko je obserwuje. Bez dodatkowej blokady na etapie socketu ruch lokalny pozostaje otwarty nawet wtedy, gdy platforma próbuje go ograniczać.

#slide 14
## layout
bullet
## slide title
Raw socket access
## subtitle
Jak działa
## bullets
- Pakiety bez mediacji
- `INTERNET` za szeroki
- Discovery niżej niż framework
- Własna obsługa odpowiedzi
## teleprompter:
Raw socket schodzi niżej niż framework i dlatego daje pełną kontrolę nad formatem pakietu i sposobem odpowiedzi. To jest dobre do własnego discovery, ale złe, jeśli aplikacja myli techniczną możliwość z prawem do korzystania z LAN.
Gdy ruch idzie bez mediacji frameworka, obrona musi zadziałać w miejscu tworzenia socketu, a nie dopiero na poziomie logiki aplikacji. W przeciwnym razie raw socket dalej będzie próbował rozmawiać z lokalnymi usługami.
W praktyce oznacza to, że zwykły `INTERNET` nie powinien wystarczać do skanowania LAN. Jeśli trzeba discovery, trzeba też osobno pilnować, jakie odpowiedzi są przyjmowane i kiedy blokada ma obowiązywać.

#slide 15
## layout
bullet
## slide title
Raw socket access
## subtitle
Jak pęka
## bullets
- Fałszywe odpowiedzi z sieci
- Brak walidacji pakietu
- Timeout albo EPERM
- Zły host i port
## teleprompter:
Atak na raw socket polega na wykorzystaniu tego, że odpowiedź z LAN może zostać przyjęta bez wystarczającej walidacji. Jeśli pakiet jest poprawny składniowo, klient może uznać go za poprawny merytorycznie.
To pozwala wstrzyknąć fałszywy endpoint, podmienić usługę albo wywołać połączenie, które kończy się timeoutem czy EPERM dopiero po stronie systemu. W praktyce przeciwnik nie potrzebuje pełnego przejęcia sieci, tylko fałszywej odpowiedzi.
Efekt jest podobny jak przy mDNS czy SSDP: aplikacja myśli, że znalazła właściwą usługę, a w rzeczywistości łączy się z podstawionym hostem albo z niczym. Bez walidacji źródła pakietu taki błąd jest trudny do zauważenia.

#slide 16
## layout
bullet
## slide title
Raw socket access
## subtitle
Jak się bronić
## bullets
- Odcinanie LAN od Internetu
- Przyznanie lokalnego dostępu
- Blokada przy socket creation
- Sprawdzenie po revocation
## teleprompter:
Obrona raw socketów musi działać na poziomie przyznawania dostępu i tworzenia połączenia. Jeśli aplikacja nie potrzebuje discovery, nie powinna mieć otwartego LAN tylko dlatego, że ma `INTERNET`.
Android 16 i późniejszy model lokalnej sieci wymagają jasnego wskazania, kiedy dostęp do LAN jest naprawdę potrzebny. To właśnie wtedy można użyć testu z NDK helperem, żeby zobaczyć, czy blokada faktycznie działa.
Jeżeli po revocation aplikacja nadal czyta odpowiedzi z LAN, to obrona jest nieskuteczna. Dobry test ma pokazać, że surowy pakiet nie przechodzi dalej niż to, na co pozwala polityka.

#slide 17
## layout
definition
## slide title
NsdManager
## subtitle
Co to jest
## term
NsdManager
## definition
NsdManager jest Androidowym API do network service discovery: aplikacja zgłasza typ usługi, system znajduje odpowiedzi w LAN, a potem zwraca host, port i TXT przez callback.
## teleprompter:
Discovery w NsdManager nie daje transportu. Najpierw pojawia się typ usługi i nazwa instancji, potem resolve do hosta i portu, a dopiero później osobne połączenie po TCP albo UDP.
mDNS nadaje przez UDP 5353 rekordy PTR, SRV i TXT. PTR wskazuje instancję, SRV niesie host i port, TXT dopisuje atrybuty. To są trzy różne warstwy decyzji, a nie jeden rekord do zaufania.
W Android 16 tryb RESTRICT_LOCAL_NETWORK pozwala zobaczyć, gdzie aplikacja ukrycie zależy od LAN. Jeśli socket, biblioteka albo WebView przestają działać, ta zależność nie jest teoretyczna.

#slide 18
## layout
bullet
## slide title
NsdManager
## subtitle
Jak działa
## bullets
- discovery, resolve, connect
- host, port, TXT
- callbacki z LAN
## teleprompter:
NsdManager zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 19
## layout
bullet
## slide title
NsdManager
## subtitle
Jak pęka
## bullets
- spoofowany PTR
- fałszywy SRV
- zły TXT
## teleprompter:
Fałszywy PTR wystarcza, żeby aplikacja zobaczyła cudzą usługę jako właściwą. Potem fałszywy SRV podstawia host i port, a zły TXT dopina atrybuty, które parser potraktuje jak stan usługi.
Jeżeli aplikacja zapisuje wynik resolve do cache bez ponownej walidacji, spoofing zostaje dłużej niż sam atak w sieci. Błąd nie musi trwać ciągle, żeby zostawić trwały zły endpoint.
Słaby punkt jest zwykle prosty: zaufanie do lokalnego rekordu bez sprawdzenia, czy host, port i typ usługi faktycznie odpowiadają oczekiwanej usłudze.

#slide 20
## layout
bullet
## slide title
NsdManager
## subtitle
Jak się bronić
## bullets
- jawny dostęp do LAN
- walidacja hosta i portu
- test z RESTRICT_LOCAL_NETWORK
## teleprompter:
Najpierw trzeba świadomie przyznać dostęp do LAN. Jeśli discovery nie jest potrzebne, nie ma powodu zostawiać go jako przypadkowej konsekwencji innej funkcji.
Po resolve trzeba sprawdzić, czy host, port i typ usługi naprawdę pasują do oczekiwanej usługi. Dopiero wtedy można przejść do transportu.
W Android 16 tryb RESTRICT_LOCAL_NETWORK jest testem tego, co aplikacja robi ukrycie. Jeżeli w tym trybie przestaje działać socket, WebView albo biblioteka, obrona musi być w konfiguracji i logice, nie w deklaracji.

#slide 21
## layout
definition
## slide title
Casting path
## subtitle
Co to jest
## term
Casting path
## definition
Casting path to przepływ, w którym aplikacja wybiera urządzenie wyjściowe przez systemowy interfejs, zamiast sama skanować i łączyć się z usługą w LAN.
## teleprompter:
Casting path zaczyna się od wyboru odbiornika. System pokazuje tylko te urządzenia, które nadają się do konkretnej ścieżki wyjściowej, więc aplikacja nie musi sama enumerować całego LAN.
Po wyborze endpointu pojawia się sesja: identyfikator urządzenia, negocjacja połączenia i dopiero potem transport treści. Ten podział oddziela discovery od samego przesyłu.
Jeśli aplikacja omija systemowy wybór i sama buduje listę odbiorników, wraca do problemów surowego discovery: fałszywy rekord, zły endpoint i błędna selekcja.

#slide 22
## layout
bullet
## slide title
Casting path
## subtitle
Jak działa
## bullets
- wybór odbiornika
- start sesji
- transport treści
## teleprompter:
Casting path zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu.
mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+. Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji.
Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa.
Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem.

#slide 23
## layout
bullet
## slide title
Casting path
## subtitle
Jak pęka
## bullets
- fałszywy odbiornik
- korelacja broadcastów
- zły endpoint
## teleprompter:
Fałszywy odbiornik działa wtedy, gdy aplikacja ufa nazwie lub wizualnej prezentacji zamiast sprawdzić parametry wybranej sesji. To wystarczy, żeby wybrać zły endpoint.
Korelacja broadcastów pozwala zbudować obraz urządzenia z kilku słabszych sygnałów: mDNS, SSDP i innych odpowiedzi lokalnych. Atak nie potrzebuje jednego perfekcyjnego rekordu, jeśli potrafi złożyć kilka spójnych sygnałów.
Skutek to nie tylko błędny wybór w interfejsie. Jeśli treść trafia do złego odbiornika, wyciek jest realny, a nie kosmetyczny.

#slide 24
## layout
bullet
## slide title
Casting path
## subtitle
Jak się bronić
## bullets
- systemowy wybór odbiornika
- bez własnego skanera
- fałszywy endpoint test
## teleprompter:
Systemowy wybór odbiornika powinien być jedynym miejscem selekcji. Jeśli aplikacja sama buduje listę urządzeń, sama robi sobie problem z fałszywym endpointem.
Bez własnego skanera zostaje mniej danych do korelacji i mniej miejsc, w których można podsunąć zły wynik. To jest prosta redukcja powierzchni ataku.
Test obrony musi podać fałszywy endpoint i sprawdzić, czy aplikacja odrzuca go przed wysłaniem treści. Jeśli nie odrzuca, obrona jest tylko deklaracją.

#slide 25
## layout
definition
## slide title
Android 16 opt-in
## subtitle
Co to jest
## term
Android 16 opt-in
## definition
Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby ujawnić ukryte zależności od LAN.
## teleprompter:
RESTRICT_LOCAL_NETWORK nie służy do produkcyjnej blokady, tylko do wykrycia ukrytych zależności od LAN przed migracją.
Jeśli socket, biblioteka albo WebView przestają działać po włączeniu tego trybu, znaczy to, że aplikacja korzysta z lokalnej sieci bez jawnej decyzji projektowej.
To jest test do znalezienia miejsc, gdzie discovery było wbudowane po cichu, a nie świadomie użyte.

#slide 26
## layout
bullet
## slide title
Android 16 opt-in
## subtitle
Jak działa
## bullets
- wykrycie zależności
- uruchomienie trybu
- obserwacja awarii
## teleprompter:
Najpierw włącza się tryb wykrywania, potem obserwuje, które ścieżki przestają działać, gdy LAN nie jest już domyślnie dostępny.
To odsłania sockety, biblioteki i WebView, które wcześniej korzystały z lokalnej sieci bez jawnego punktu decyzji.
Wynik ma być konkretny: albo aplikacja nadal działa po świadomym dopięciu dostępu, albo trzeba usunąć ukryte zależności.
#slide 27
## layout
bullet
## slide title
Android 16 opt-in
## subtitle
Jak pęka
## bullets
- fake endpoint
- ukryty LAN dependency
- błędny fallback
## teleprompter:
Atak na ten tryb zwykle nie polega na łamaniu polityki, tylko na wykorzystaniu tego, że aplikacja wcześniej zakładała LAN bez sprawdzenia konsekwencji.
Jeśli po włączeniu trybu pojawia się zły fallback, trzeba to traktować jako realny błąd projektu, nie jako drobną awarię.
Breach widać tam, gdzie aplikacja nadal ufa lokalnemu endpointowi, mimo że system już pokazał, że zależność od LAN nie była jawna.

#slide 28
## layout
bullet
## slide title
Android 16 opt-in
## subtitle
Jak się bronić
## bullets
- jawna zgoda na LAN
- asercja hosta i portu
- kontrola po compat toggle
## teleprompter:
Jeśli aplikacja naprawdę potrzebuje LAN, zgoda powinna być jawna i ograniczona do konkretnej funkcji.
Host i port trzeba asercyjnie sprawdzić po resolve, zamiast ufać jednemu rekordowi albo jednej odpowiedzi sieci.
Test z compat toggle ma pokazać, że aplikacja działa poprawnie tylko wtedy, gdy LAN jest decyzją projektową, a nie przypadkiem włączonym przez zależną bibliotekę.

#slide 29
## layout
definition
## slide title
Android 17 enforcement
## subtitle
Co to jest
## term
Android 17 enforcement
## definition
Android 17 blokuje LAN domyślnie dla targetSdk 37+ i wprowadza ACCESS_LOCAL_NETWORK.
## teleprompter:
ACCESS_LOCAL_NETWORK nie jest nazwą alternatywną dla starego broad access. To nowy punkt egzekwowania, który ma domyślnie blokować LAN dla nowych aplikacji.
Podniesienie targetSdk do 37+ nie powinno tylko odblokować starego zachowania. Ma wymusić świadome przejście przez nowy model i nowy dialog.
Jeśli aplikacja nadal działa bez ponownej walidacji po wejściu w ten model, to znaczy, że obrona jest niepełna albo obejście ukryło się w bibliotece pomocniczej.

#slide 30
## layout
bullet
## slide title
Android 17 enforcement
## subtitle
Jak działa
## bullets
- blokada domyślna
- nowy dialog
- status przed transportem
## teleprompter:
Najpierw pojawia się nowy punkt kontroli, potem system decyduje, czy LAN w ogóle przejdzie do transportu.
Blokada domyślna nie jest tylko ostrzejszym promptem. To zmiana stanu, którą aplikacja musi obsłużyć przed wysłaniem danych.
Jeżeli nie ma świadomej zgody, ścieżka ma zakończyć się wcześniej, zanim endpoint dostanie jakikolwiek ruch.
#slide 31
## layout
bullet
## slide title
Android 17 enforcement
## subtitle
Jak pęka
## bullets
- zły fallback
- fałszywy endpoint
- ukryta zależność
## teleprompter:
Wymuszenie nie psuje aplikacji samo z siebie. Psuje ją tylko wtedy, gdy wcześniej opierała się na LAN bez jawnej decyzji i bez poprawnego fallbacku.
Jeśli po blokadzie pojawia się fałszywy endpoint albo aplikacja dalej próbuje korzystać z lokalnej usługi, to problem jest w projekcie, nie w platformie.
Najważniejszy sygnał to miejsce, w którym zły rekord albo brak dostępu nadal prowadzą do połączenia zamiast do odrzucenia.

#slide 32
## layout
bullet
## slide title
Android 17 enforcement
## subtitle
Jak się bronić
## bullets
- jawne żądanie LAN
- test po migracji
- odrzucenie po błędzie
## teleprompter:
Jeśli aplikacja ma używać LAN, musi to zrobić jawnie i tylko tam, gdzie naprawdę tego potrzebuje.
Po migracji trzeba sprawdzić, czy błędna ścieżka nie przechodzi dalej do transportu. Odrzucenie ma nastąpić przed połączeniem, nie po nim.
Dobry test pokazuje, że aplikacja potrafi odmówić własnemu błędnemu endpointowi i nie otwiera po cichu szerszego dostępu.

#slide 33
## layout
definition
## slide title
Permission split
## subtitle
Co to jest
## term
Permission split
## definition
Permission split to przejściowy model, w którym lokalna sieć ma osobny, jawny krok dostępu zamiast być ukryta w zwykłym Wi-Fi.
## teleprompter:
Permission split rozdziela dwa różne pytania: czy aplikacja ma internet i czy może dotknąć lokalnej sieci.
To ważne, bo discovery w LAN nie jest tym samym co zwykły dostęp do serwera zewnętrznego. Aplikacja może mieć łączność i nadal nie mieć prawa do broadcastów, resolve ani lokalnych usług.
Zmiana modelu pokazuje, gdzie wcześniej lokalna sieć była traktowana jako oczywistość, a gdzie powinna być osobną decyzją.

#slide 34
## layout
bullet
## slide title
Permission split
## subtitle
Jak działa
## bullets
- osobny krok dla LAN
- różne ścieżki dostępu
- lokalna sieć nie jest domyślna
## teleprompter:
Najpierw aplikacja próbuje dostać dostęp przez stary lub przejściowy model, a dopiero potem przechodzi do nowego punktu dostępu dla LAN.
Jeśli platforma widzi, że aplikacja korzysta z lokalnej sieci, rozróżnia zwykły internet od sieci pobliskiej, bo skutki prywatności są inne.
Ten krok ma zmusić aplikację do jawnego opowiedzenia, po co w ogóle potrzebuje discovery.

#slide 35
## layout
bullet
## slide title
Permission split
## subtitle
Jak pęka
## bullets
- stary kod zakłada LAN
- biblioteka omija decyzję
- fallback wraca do broadcastów
## teleprompter:
Atak pojawia się wtedy, gdy stary kod albo biblioteka nadal zachowują się tak, jakby LAN był zawsze dostępny.
Wtedy nowy model nie wymusza realnej zmiany, tylko odsłania to, że decyzja została ominięta w środku stosu.
Najbardziej zdradliwy jest fallback, który po odmowie wraca do własnego skanowania broadcastów i odzyskuje to, co miało być jawnie ograniczone.

#slide 36
## layout
bullet
## slide title
Permission split
## subtitle
Jak się bronić
## bullets
- jawny wybór ścieżki
- osobny test dla LAN
- kontrola po revocation
## teleprompter:
Obrona zaczyna się od tego, że aplikacja nie traktuje LAN jako domyślnego dodatku do Wi-Fi.
Każdy przypadek powinien mieć osobny test: sukces, odmowę i stan po revocation.
Jeśli po cofnięciu dostępu aplikacja nadal trafia do lokalnej usługi, to kontrola nie objęła całej ścieżki.

#slide 37
## layout
definition
## slide title
Broad access path
## subtitle
Co to jest
## term
Broad access path
## definition
Broad access path to klasyczny runtime request o dostęp do lokalnej sieci.
## teleprompter:
Broad access path oznacza jawny dialog, w którym aplikacja prosi o dostęp do lokalnej sieci w czasie działania.
To jest model bardziej bezpośredni niż ukryte użycie LAN: użytkownik widzi prośbę, a aplikacja dostaje wynik decyzji wprost.
Tu liczy się nie sam dialog, tylko to, co aplikacja robi z odmową, zgodą i późniejszym cofnięciem.

#slide 38
## layout
bullet
## slide title
Broad access path
## subtitle
Jak działa
## bullets
- request, grant, revoke
- wynik wraca do aplikacji
- decyzja wpływa na sockety
## teleprompter:
Najpierw aplikacja wywołuje żądanie, potem system pokazuje użytkownikowi decyzję, a na końcu wynik wraca do kodu.
Grant otwiera dostęp do ścieżek, które wcześniej były blokowane. Revoke zamyka je ponownie i powinien odciąć kolejne próby połączenia.
Dobrze zaprojektowana aplikacja nie traktuje grantu jako stałej cechy środowiska, tylko jako chwilowy stan, który może zniknąć.

#slide 39
## layout
bullet
## slide title
Broad access path
## subtitle
Jak pęka
## bullets
- zbyt szeroki grant
- stary cache po revoke
- błędny fallback do własnego skanera
## teleprompter:
Broad access path pęka, gdy aplikacja po grancie rozszerza użycie LAN bardziej niż trzeba.
Drugim błędem jest cache, który przeżywa revoke i nadal prowadzi do lokalnego endpointu.
Trzeci błąd to fallback do własnego skanera, który działa nawet wtedy, gdy użytkownik cofnął zgodę.

#slide 40
## layout
bullet
## slide title
Broad access path
## subtitle
Jak się bronić
## bullets
- sprawdzenie po odnowieniu stanu
- brak trwałego cache
- obsługa revoke w kodzie
## teleprompter:
Obrona polega na tym, że każda próba wejścia w LAN sprawdza aktualny stan, a nie pamięta jednego dawnego pozwolenia.
Po revoke aplikacja musi czyścić cache, odświeżać stan i odcinać połączenia, które już nie mają prawa istnieć.
Jeśli po cofnięciu zgody endpoint wciąż działa, to znaczy, że model dostępu nie został zaimplementowany do końca.

#slide 41
## layout
definition
## slide title
Privacy-preserving picker
## subtitle
Co to jest
## term
Privacy-preserving picker
## definition
Privacy-preserving picker to systemowy wybór zasobu, który nie wymaga szerokiego grantu dla lokalnej sieci.
## teleprompter:
Picker ma ograniczyć ilość danych, które aplikacja musi sama zbierać z sieci.
W praktyce chodzi o to, żeby system wykonał część selekcji, a aplikacja dostała tylko gotowy wynik, zamiast własnoręcznie mapować cały LAN.
To jest sposób na uniknięcie sytuacji, w której sama wygoda discovery zamienia się w szerokie, niepotrzebne uprawnienie.

#slide 42
## layout
bullet
## slide title
Privacy-preserving picker
## subtitle
Jak działa
## bullets
- system wybiera wynik
- aplikacja nie widzi całej sieci
- selekcja nie daje broad grant
## teleprompter:
System bierze na siebie selekcję i ogranicza widoczność tego, co aplikacja może zobaczyć.
Aplikacja dostaje wynik, nie cały katalog lokalnych usług.
To odcina część błędów, które pojawiają się wtedy, gdy aplikacja sama musi mieć pełny ogląd na LAN, żeby wykonać prosty wybór.

#slide 43
## layout
bullet
## slide title
Privacy-preserving picker
## subtitle
Jak pęka
## bullets
- picker wraca do własnego skanera
- wynik jest nadpisywany
- systemowy wybór omijany
## teleprompter:
Picker pęka, gdy aplikacja mimo wszystko zaczyna budować własną listę wyników i omija systemową selekcję.
Wtedy wynik pickerowego wyboru nie ogranicza już widoczności, bo aplikacja i tak robi sobie pełny podgląd sieci.
To jest dokładnie ten moment, w którym prywatność znika przez obejście, a nie przez sam mechanizm.

#slide 44
## layout
bullet
## slide title
Privacy-preserving picker
## subtitle
Jak się bronić
## bullets
- systemowy wynik bez korelacji
- brak własnego skanowania
- test odmowy broad access
## teleprompter:
Obrona polega na tym, że aplikacja używa tylko wyniku z systemu i nie miesza go z własnym skanerem.
Jeśli trzeba odpytać LAN, to nie powinno być robione jako cicha, dodatkowa ścieżka obok pickera.
Test ma pokazać, że po odmowie broad access picker nadal działa jako ograniczony wybór, a nie jako pretekst do pełnego skanowania.

#slide 45
## layout
definition
## slide title
Host app inheritance
## subtitle
Co to jest
## term
Host app inheritance
## definition
Host app inheritance oznacza, że WebView dziedziczy stan dostępu do lokalnej sieci po aplikacji hosta.
## teleprompter:
WebView nie zawsze ma własną, oddzielną decyzję o LAN.
Jeśli host ma dostęp albo go nie ma, osadzony komponent może odziedziczyć ten stan i zachowywać się tak, jakby był częścią aplikacji nadrzędnej.
To ważne, bo komunikacja przez WebView może wyglądać jak zwykły rendering, a faktycznie dotyka lokalnej sieci.

#slide 46
## layout
bullet
## slide title
Host app inheritance
## subtitle
Jak działa
## bullets
- host decyduje o stanie
- WebView dziedziczy wynik
- sprawdzany jest ten sam dostęp
## teleprompter:
Stan dostępu powstaje po stronie hosta i jest później widoczny w osadzonym komponencie.
To znaczy, że WebView może korzystać z tego samego wyniku decyzji, który host już przeszedł.
Jeśli host nie przeszedł przez jawny model LAN, osadzona treść też nie powinna go omijać.

#slide 47
## layout
bullet
## slide title
Host app inheritance
## subtitle
Jak pęka
## bullets
- host ma ukryty dostęp
- WebView robi LAN bez zgody
- stan nie jest odświeżony
## teleprompter:
Atak zaczyna się wtedy, gdy host ma dostęp do LAN ukryty w swojej logice, a osadzony WebView przejmuje go bez osobnej kontroli.
Wtedy wydaje się, że to tylko rendering strony, ale w praktyce komponent dalej korzysta z lokalnej sieci.
Jeśli stan nie jest odświeżony po revocation, osadzona treść może dalej widzieć endpointy, które powinny być już zamknięte.

#slide 48
## layout
bullet
## slide title
Host app inheritance
## subtitle
Jak się bronić
## bullets
- osobna walidacja stanu
- aktualizacja po revoke
- brak cichego dziedziczenia
## teleprompter:
Host i WebView nie powinny zakładać, że jeden stan wystarczy na zawsze.
Po revoke trzeba odświeżyć decyzję i sprawdzić, czy osadzony komponent nadal ma prawo do lokalnej sieci.
Jeżeli nie ma osobnej walidacji, to dziedziczenie staje się ukrytą luką, a nie wygodnym skrótem.

#slide 49
## layout
definition
## slide title
Media as data class
## subtitle
Co to jest
## term
Media as data class
## definition
Zdjęcia i filmy są traktowane jako osobna klasa prywatnych danych.
## teleprompter:
Media jako osobna klasa danych oznacza, że aplikacja nie powinna widzieć całej biblioteki tylko dlatego, że potrzebuje jednego URI.
Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED, żeby dostęp do zdjęć i filmów mógł być ograniczony do wybranego zestawu.
Picker zwraca content URI, a embedded picker działa w SurfaceView przez setChildSurfacePackage, z callbackami onUriPermissionGranted i onUriPermissionRevoked.
Cloud media providers i MediaStore#getVersion() pokazują, że nawet wybór mediów ma konsekwencje prywatności i fingerprintingu.

#slide 50
## layout
bullet
## slide title
Media as data class
## subtitle
Jak działa
## bullets
- READ_MEDIA_VISUAL_USER_SELECTED
- content URI zamiast pełnego storage
- revoke zmienia zakres
## teleprompter:
Najpierw system pokazuje wybór, potem wraca pojedynczy URI albo mały zestaw URI.
Aplikacja dostaje dostęp do konkretnych mediów, a nie do całej biblioteki.
Gdy zakres się zmienia, callback musi odświeżyć stan, bo stary URI nie jest automatycznie wieczny.

#slide 51
## layout
bullet
## slide title
Media as data class
## subtitle
Jak pęka
## bullets
- stare URI po revoke
- partial access mylony z pełnym
- EXIF i lokalizacja wyciekają
## teleprompter:
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke albo traktuje partial access jak pełny dostęp.
Drugi błąd to cache bez odświeżenia i czytanie metadanych lokalizacji tak, jakby nie niosły dodatkowych informacji.
Jeśli własna galeria ignoruje latest selection only, systemowy wybór przestaje ograniczać rzeczywisty zasięg danych.

#slide 52
## layout
bullet
## slide title
Media as data class
## subtitle
Jak się bronić
## bullets
- picker contract zamiast storage flow
- odświeżenie po revocation
- backport bez pełnego dostępu
## teleprompter:
Obrona wymaga korzystania z picker contract zamiast własnego storage flow.
Po revoke trzeba odświeżać stan i usuwać stare URI z cache.
Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity ma zachować ten sam model selekcji, a nie przywracać pełen dostęp.

#slide 53
## layout
definition
## slide title
Selected Photos Access
## subtitle
Co to jest
## term
Selected Photos Access
## definition
Android 14 może dać dostęp tylko do zdjęć i filmów wybranych przez użytkownika.
## teleprompter:
Selected Photos Access oznacza, że aplikacja może dostać tylko część biblioteki, którą sam użytkownik wskazał.
To jest kontrola nad zakresem, nie nad samym faktem używania galerii.
Dzięki temu aplikacja nie musi mieć pełnego dostępu do zdjęć i filmów, żeby wykonać jedną operację na kilku plikach.

#slide 54
## layout
bullet
## slide title
Selected Photos Access
## subtitle
Jak działa
## bullets
- partial access do wybranych mediów
- picker zwraca content URI
- callbacki pokazują zmianę zakresu
## teleprompter:
Najpierw użytkownik wybiera konkretne media, a system przekazuje tylko ten zakres.
Potem aplikacja pracuje na zwróconych URI i dostaje sygnał, kiedy zakres się zmienia.
To jest model, w którym stan dostępu żyje razem z wyborem, a nie jako jednorazowy grant na całą bibliotekę.

#slide 55
## layout
bullet
## slide title
Selected Photos Access
## subtitle
Jak pęka
## bullets
- stare URI po revoke
- cache nie odświeża stanu
- latest selection ignored
## teleprompter:
Breach pojawia się, gdy aplikacja trzyma stare URI po revoke albo cache'uje wybór bez odświeżenia.
Własna galeria może też ignorować latest selection only i przez to rozszerzać zakres poza to, co użytkownik naprawdę wybrał.
Jeśli metadane lokalizacji są traktowane jak neutralne, wyciek robi się większy niż sam obraz.

#slide 56
## layout
bullet
## slide title
Selected Photos Access
## subtitle
Jak się bronić
## bullets
- rozdzielenie matrix uprawnień
- picker contract
- odświeżenie po revoke
## teleprompter:
Obrona zaczyna się od rozdzielenia matrycy uprawnień i odświeżania stanu po revoke.
Picker contract ogranicza widoczność i odcina potrzebę własnego storage flow.
Backport ma zachować ten sam model selekcji, bo starsze urządzenie nie może być wymówką do pełnego dostępu.

#slide 57
## layout
definition
## slide title
READ_MEDIA_VISUAL_USER_SELECTED
## subtitle
Co to jest
## term
READ_MEDIA_VISUAL_USER_SELECTED
## definition
READ_MEDIA_VISUAL_USER_SELECTED oznacza partial access do wybranych mediów wizualnych.
## teleprompter:
READ_MEDIA_VISUAL_USER_SELECTED jest technicznym przełącznikiem na partial access.
To nie jest zamiennik pełnego storage permission, tylko sposób na ograniczenie widoku do wybranych zdjęć i filmów.
System dalej zwraca URI, ale zakres tych URI ma być mniejszy niż cała biblioteka.

#slide 58
## layout
bullet
## slide title
READ_MEDIA_VISUAL_USER_SELECTED
## subtitle
Jak działa
## bullets
- partial access zamiast pełnej biblioteki
- URI wraca z pickera
- callback zmienia zakres
## teleprompter:
System wybiera zakres, a aplikacja dostaje URI tylko z tego zakresu.
Gdy użytkownik zmienia wybór, callback informuje o zmianie i aplikacja musi zaktualizować stan.
Bez tego aplikacja nadal działa na starych założeniach, choć zakres danych już się zmienił.

#slide 59
## layout
bullet
## slide title
READ_MEDIA_VISUAL_USER_SELECTED
## subtitle
Jak pęka
## bullets
- stary URI po revoke
- cache bez odświeżenia
- metadane lokalizacji wyciekają
## teleprompter:
Stare URI po revoke są tu najprostszą drogą do błędu.
Jeśli cache nie jest odświeżony, aplikacja pokazuje dane, do których już nie powinna mieć dostępu.
Metadane lokalizacji dodatkowo zwiększają skalę wycieku, bo nie chodzi już tylko o obraz, ale o miejsce i kontekst.

#slide 60
## layout
bullet
## slide title
READ_MEDIA_VISUAL_USER_SELECTED
## subtitle
Jak się bronić
## bullets
- odświeżanie stanu po revoke
- brak pełnego storage flow
- backport zachowuje selekcję
## teleprompter:
Obrona polega na tym, że revoke natychmiast wymusza odświeżenie stanu i wyczyszczenie starych URI.
Nie wolno zamieniać partial access w pełny storage flow tylko dlatego, że tak wygodniej w kodzie.
Jeśli jest backport, ma zachować ten sam model selekcji, a nie przywracać dawny szeroki dostęp.
#slide 61
## layout
definition
## slide title
Compatibility mode
## subtitle
Co to jest
## term
Compatibility mode
## definition
Legacy app może działać w trybie kompatybilności, w którym system chroni wybrany podzbiór mediów.
## teleprompter:
Compatibility mode pozwala starszej aplikacji działać bez pełnego dostępu do całej biblioteki.
System nadal ogranicza media do wybranego podzbioru, zamiast wracać do starego modelu pełnej widoczności.
To jest sposób na migrację, w której stary kod ma nadal działać, ale już nie może zakładać pełnej galerii.

#slide 62
## layout
bullet
## slide title
Compatibility mode
## subtitle
Jak działa
## bullets
- tryb dla starszej aplikacji
- system chroni wybór
- zakres zostaje ograniczony
## teleprompter:
System uruchamia aplikację w trybie, który zachowuje ograniczony widok mediów.
Zakres danych pozostaje przycięty do wybranego podzbioru, a nie do całej biblioteki.
Dzięki temu starszy kod może działać, ale nie może po cichu odzyskać szerokiego dostępu.

#slide 63
## layout
bullet
## slide title
Compatibility mode
## subtitle
Jak pęka
## bullets
- stary kod zakłada pełny dostęp
- cache przeżywa revoke
- galeria omija wybór systemu
## teleprompter:
Breach pojawia się wtedy, gdy legacy app nadal zachowuje się jakby pełny dostęp był normalny.
Stary cache po revoke i własna galeria, która omija systemowy wybór, rozszerzają zakres danych poza to, co system chce chronić.
Jeśli aplikacja działa tylko dlatego, że potajemnie wraca do starego modelu, tryb zgodności nie spełnia swojej roli.

#slide 64
## layout
bullet
## slide title
Compatibility mode
## subtitle
Jak się bronić
## bullets
- ten sam model selekcji
- odświeżenie po revoke
- brak powrotu do full access
## teleprompter:
Obrona polega na tym, że nawet w trybie zgodności aplikacja zachowuje ten sam model selekcji mediów.
Po revoke trzeba odświeżyć stan i usunąć stare URI z cache.
Nie wolno wracać do pełnego dostępu tylko dlatego, że to ułatwia przejście starego kodu przez migrację.

#slide 65
## layout
definition
## slide title
Permission matrix
## subtitle
Co to jest
## term
Permission matrix
## definition
Obrazy, filmy i metadane lokalizacji mają różne ścieżki uprawnień i ekspozycji.
## teleprompter:
Permission matrix rozdziela trzy różne klasy danych: obrazy, filmy i metadane lokalizacji.
Każda z nich może mieć inny zakres widoczności i inne ryzyko wycieku.
To jest fundament dalszych decyzji o partial access i picker contract.

#slide 66
## layout
bullet
## slide title
Permission matrix
## subtitle
Jak działa
## bullets
- różne ścieżki uprawnień
- lokalizacja ma osobny zakres
- matrix steruje ekspozycją
## teleprompter:
System nie traktuje obrazów, filmów i metadanych lokalizacji identycznie.
Każda klasa danych ma własny zakres ekspozycji i własny sposób ograniczenia.
Dzięki temu można odciąć jedną klasę danych bez otwierania całej reszty.

#slide 67
## layout
bullet
## slide title
Permission matrix
## subtitle
Jak pęka
## bullets
- jedna ścieżka zastępuje wszystkie
- cache miesza klasy danych
- lokalizacja wycieka razem z obrazem
## teleprompter:
Breach pojawia się wtedy, gdy aplikacja traktuje różne klasy danych jak jedną wspólną bibliotekę.
Cache może mieszać obrazy, filmy i metadane lokalizacji, a wtedy wyciek staje się szerszy niż pojedynczy plik.
Jeśli jedna ścieżka uprawnień zastępuje wszystkie, matrix przestaje działać.

#slide 68
## layout
bullet
## slide title
Permission matrix
## subtitle
Jak się bronić
## bullets
- osobna kontrola dla klas danych
- odświeżanie po revoke
- picker contract zamiast full storage
## teleprompter:
Obrona polega na tym, że każda klasa danych ma osobną kontrolę i osobny stan.
Po revoke trzeba odświeżyć wszystkie zależne widoki i cache.
Picker contract zastępuje pełny storage flow, zamiast tylko go maskować.

#slide 69
## layout
definition
## slide title
Latest selection only
## subtitle
Co to jest
## term
Latest selection only
## definition
Latest-selection query zwraca tylko najbardziej aktualny wybrany zestaw URI.
## teleprompter:
Latest selection only oznacza, że aplikacja widzi tylko ostatnio wybrany zestaw URI.
To ma odciąć stare wybory, które przestały już być aktualne.
Dzięki temu system może ograniczać widoczność bez utrzymywania całej historii wyborów.

#slide 70
## layout
bullet
## slide title
Latest selection only
## subtitle
Jak działa
## bullets
- system zwraca ostatni wybór
- callback aktualizuje stan
- stare zestawy nie są domyślne
## teleprompter:
System zwraca aktualny wybór, a aplikacja dostaje sygnał, kiedy ten wybór się zmienia.
To wymusza pracę na najnowszym stanie, a nie na historycznych URI.
Stare zestawy nie powinny być automatycznie traktowane jako dalej ważne.

#slide 71
## layout
bullet
## slide title
Latest selection only
## subtitle
Jak pęka
## bullets
- stare URI wracają po revoke
- cache trzyma historię
- galeria ignoruje aktualny wybór
## teleprompter:
Breach pojawia się wtedy, gdy aplikacja wraca do starych URI po revoke albo trzyma historię w cache.
Jeśli własna galeria ignoruje aktualny wybór, systemowy mechanizm przestaje ograniczać rzeczywisty dostęp.
To właśnie wtedy latest selection only staje się tylko nazwą, a nie działającą regułą.

#slide 72
## layout
bullet
## slide title
Latest selection only
## subtitle
Jak się bronić
## bullets
- zawsze odczytuj najnowszy wybór
- czyść stare URI
- nie buduj własnej historii wyborów
## teleprompter:
Obrona polega na tym, że aplikacja zawsze odczytuje najnowszy wybór i czyści stare URI po zmianie stanu.
Nie wolno budować własnej historii wyborów obok systemowego mechanizmu.
Jeśli stan się zmienia, kod musi to odzwierciedlić natychmiast, a nie dopiero przy następnym uruchomieniu.
#slide 73
## layout
definition
## slide title
Upgrade behavior
## subtitle
Co to jest
## term
Upgrade behavior
## definition
Upgrade behavior decyduje, czy wcześniej zainstalowana aplikacja zachowa dostęp, czy ma go przeliczyć od nowa.
## teleprompter:
Upgrade behavior dotyczy aplikacji już zainstalowanych przed zmianą modelu mediów.
System musi zdecydować, czy stare przywileje zostają, czy trzeba je przeliczyć według nowej matrycy uprawnień.
To jest miejsce, w którym migracja nie może polegać na bezwładnym zachowaniu dawnych grantów.

#slide 74
## layout
bullet
## slide title
Upgrade behavior
## subtitle
Jak działa
## bullets
- zachowanie po migracji
- stare granty są przeliczane
- wynik wraca do aplikacji
## teleprompter:
Przy migracji system sprawdza, co wolno zachować, a co trzeba ograniczyć.
Dla aplikacji oznacza to nowy wynik, który może różnić się od starego zachowania sprzed aktualizacji.
Jeżeli kod nie odczytuje tego wyniku, nadal działa tak, jakby nic się nie zmieniło.

#slide 75
## layout
bullet
## slide title
Upgrade behavior
## subtitle
Jak pęka
## bullets
- stare URI po revocation
- cache nie znikają
- galeria omija nowy model
## teleprompter:
Breach pojawia się wtedy, gdy stary stan zostaje w aplikacji po migracji.
Cache, stare URI i własna galeria mogą utrzymywać dostęp, który system chciał już przeliczyć od nowa.
To jest najprostszy przypadek, w którym upgrade istnieje tylko w nazwie, a nie w faktycznym zachowaniu.

#slide 76
## layout
bullet
## slide title
Upgrade behavior
## subtitle
Jak się bronić
## bullets
- odbiór nowego wyniku
- czyszczenie starego stanu
- kontrola po odnowieniu
## teleprompter:
Obrona polega na tym, że aplikacja bierze pod uwagę nowy wynik systemu i czyści stary stan.
Po migracji trzeba ponownie sprawdzić, czy dostęp nadal jest zgodny z aktualną polityką.
Jeśli aplikacja tego nie robi, stara ścieżka pozostaje aktywna mimo nowego modelu.

#slide 77
## layout
definition
## slide title
Photo picker contract
## subtitle
Co to jest
## term
Photo picker contract
## definition
Systemowy photo picker zwraca content URI bez proszenia o szeroki dostęp do storage.
## teleprompter:
Photo picker contract ogranicza aplikację do wybranego zasobu zamiast do całej biblioteki.
System zwraca content URI, a aplikacja nie musi mieć pełnego storage permission, żeby dostać pojedynczy plik.
To jest podstawowy kontrakt, z którego korzystają dalsze warianty selekcji mediów.

#slide 78
## layout
bullet
## slide title
Photo picker contract
## subtitle
Jak działa
## bullets
- system zwraca URI
- aplikacja dostaje tylko wybór
- zakres zmienia callback
## teleprompter:
Najpierw system zwraca wybrane URI, a nie katalog plików.
Aplikacja dostaje tylko to, co użytkownik wybrał, i musi reagować na zmianę zakresu.
Callback po stronie aplikacji ma odświeżać stan, a nie tylko potwierdzać wybór.

#slide 79
## layout
bullet
## slide title
Photo picker contract
## subtitle
Jak pęka
## bullets
- stary URI po revoke
- własny flow storage
- latest selection ignorowane
## teleprompter:
Breach pojawia się wtedy, gdy aplikacja nie usuwa starego URI po revoke albo buduje własny storage flow obok pickera.
Jeśli latest selection jest ignorowane, systemowy wybór przestaje ograniczać rzeczywisty zasięg danych.
Wtedy picker jest tylko wizualnym elementem, a nie granicą dostępu.

#slide 80
## layout
bullet
## slide title
Photo picker contract
## subtitle
Jak się bronić
## bullets
- picker contract zamiast storage flow
- odświeżanie stanu
- backport bez pełnego dostępu
## teleprompter:
Obrona polega na korzystaniu wyłącznie z picker contract i odświeżaniu stanu po zmianie wyboru.
Nie wolno przekształcać tego flow w pełny dostęp do storage tylko po to, by uprościć kod.
Jeśli jest backport, ma zachować ten sam model selekcji, a nie przywracać dawną szerokość dostępu.

#slide 81
## layout
definition
## slide title
Backport path
## subtitle
Co to jest
## term
Backport path
## definition
Jetpack potrafi zbackportować picker na starsze urządzenia przez jeden kontrakt API.
## teleprompter:
Backport path pozwala starszym urządzeniom korzystać z tego samego kontraktu wyboru mediów.
Nie chodzi o to, by emulować pełny storage access, tylko by zachować wspólny model selekcji.
Dzięki temu starszy system nie wymaga osobnego, szerokiego flow w kodzie aplikacji.

#slide 82
## layout
bullet
## slide title
Backport path
## subtitle
Jak działa
## bullets
- wspólny kontrakt API
- starsze urządzenia mają ten sam wybór
- rozszerzenie nie zmienia modelu
## teleprompter:
Backport dostarcza ten sam kontrakt API także tam, gdzie platforma nie ma natywnego pickera.
Aplikacja widzi spójny model wyboru i nie musi rozbijać logiki na dwa różne światy.
To ogranicza rozjazd między nowszym i starszym urządzeniem.

#slide 83
## layout
bullet
## slide title
Backport path
## subtitle
Jak pęka
## bullets
- pełny storage wraca ukrycie
- stary kod omija kontrakt
- zakres nie jest ograniczony
## teleprompter:
Breach pojawia się, gdy backport jest tylko nakładką, a stary kod dalej wraca do pełnego storage.
Jeśli aplikacja omija kontrakt albo rozszerza zakres poza wybrany zasób, backport nie chroni już prywatności.
Wtedy starsze urządzenie staje się pretekstem do cofnięcia całego modelu ograniczonego wyboru.

#slide 84
## layout
bullet
## slide title
Backport path
## subtitle
Jak się bronić
## bullets
- ten sam model selekcji
- brak pełnego storage flow
- aktualizacja po revoke
## teleprompter:
Obrona wymaga, by backport zachowywał dokładnie ten sam model selekcji, co natywna ścieżka.
Po revoke trzeba odświeżyć stan i usunąć stary dostęp z cache i UI.
Jeśli model się rozjeżdża, starsze urządzenie zaczyna zachowywać się mniej bezpiecznie niż nowsze.

#slide 85
## layout
definition
## slide title
Cloud media providers
## subtitle
Co to jest
## term
Cloud media providers
## definition
Cloud media providers pozwalają widzieć lokalne i zdalne biblioteki w jednym wyborze.
## teleprompter:
Cloud media providers łączą lokalne i zdalne media w jednym systemowym wyborze.
To upraszcza wybór dla użytkownika, ale poszerza powierzchnię, którą picker musi pośrednio obsłużyć.
Aplikacja nadal dostaje URI, tylko że źródło tych URI może być lokalne albo zdalne.

#slide 86
## layout
bullet
## slide title
Cloud media providers
## subtitle
Jak działa
## bullets
- lokalne i zdalne źródła
- jeden systemowy wybór
- URI z jednego kontraktu
## teleprompter:
System zbiera źródła lokalne i zdalne do jednego wyboru.
Dla aplikacji kończy się to jednym URI lub zestawem URI z jednego kontraktu.
To oznacza, że sama selekcja nie mówi jeszcze, skąd dokładnie pochodzi zawartość.

#slide 87
## layout
bullet
## slide title
Cloud media providers
## subtitle
Jak pęka
## bullets
- cache trzyma stare URI
- revoke nie czyści wyboru
- metadane lokalizacji wyciekają
## teleprompter:
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI mimo revoke albo zbyt długo ufa cache.
Jeżeli metadane lokalizacji są traktowane jak neutralne, prywatność psuje się szybciej niż sam obraz.
W modelu z chmurą błąd selekcji i błąd metadanych wzmacniają się nawzajem.

#slide 88
## layout
bullet
## slide title
Cloud media providers
## subtitle
Jak się bronić
## bullets
- odświeżanie po revoke
- picker contract jako jedyne wejście
- kontrola EXIF i lokalizacji
## teleprompter:
Obrona polega na tym, że revoke natychmiast odświeża stan i czyści stare URI.
Picker contract ma być jedynym wejściem do wyboru, a EXIF i lokalizacja muszą być traktowane jako dane wrażliwe.
Jeśli aplikacja wspiera chmurę, to właśnie tu trzeba zamknąć wyciek metadanych.

#slide 89
## layout
definition
## slide title
MediaStore version lockdown
## subtitle
Co to jest
## term
MediaStore version lockdown
## definition
MediaStore#getVersion() jest przycięty tak, by nie służył jako stabilny fingerprint aplikacji.
## teleprompter:
MediaStore#getVersion() ma ograniczyć możliwość fingerprintingu przez biblioteki mediów.
To nie jest funkcja do śledzenia wersji aplikacji w sposób stabilny w czasie.
Jeśli ten numer daje trwałą tożsamość, mechanizm przestaje chronić prywatność.

#slide 90
## layout
bullet
## slide title
MediaStore version lockdown
## subtitle
Jak działa
## bullets
- version nie jest stabilnym identyfikatorem
- wynik nie ma być fingerprintem
- aplikacja nie opiera się na wersji
## teleprompter:
System nie powinien pozwalać, by MediaStore version działał jak stały identyfikator aplikacji.
Wynik ma być użyteczny dla systemu, ale nie do budowania śledzenia lub korelacji.
Aplikacja nie powinna opierać swojej logiki na tym, że version pozostanie przewidywalny.

#slide 91
## layout
bullet
## slide title
MediaStore version lockdown
## subtitle
Jak pęka
## bullets
- version staje się fingerprintem
- korelacja między uruchomieniami
- version użyty jako identyfikator
## teleprompter:
Breach pojawia się wtedy, gdy MediaStore version zaczyna służyć do korelacji między uruchomieniami.
Jeśli aplikacja traktuje ten numer jako identyfikator, śledzenie staje się prostsze niż powinno.
To jest właśnie ten przypadek, który lockdown ma uniemożliwić.

#slide 92
## layout
bullet
## slide title
MediaStore version lockdown
## subtitle
Jak się bronić
## bullets
- nie używać version jako ID
- nie korelować wyników
- trzymać się picker contract
## teleprompter:
Obrona polega na tym, że version nie jest używany jako ID ani jako narzędzie korelacji.
Zamiast tego aplikacja trzyma się picker contract i innych jawnych danych wyboru.
Jeśli potrzebny jest stan aplikacji, trzeba go liczyć poza tym polem.

#slide 93
## layout
definition
## slide title
Embedded photo picker
## subtitle
Co to jest
## term
Embedded photo picker
## definition
Embedded photo picker działa w SurfaceView przez setChildSurfacePackage i trzyma klienta w stanie resumed.
## teleprompter:
Embedded photo picker osadza wybór mediów bez wyrywania użytkownika z głównego widoku aplikacji.
Picker dalej zachowuje własną granicę bezpieczeństwa, mimo że jest pokazany wewnątrz UI hosta.
To daje bardziej ciągły flow, ale nie daje pełnego dostępu do biblioteki.

#slide 94
## layout
bullet
## slide title
Embedded photo picker
## subtitle
Jak działa
## bullets
- SurfaceView jako granica
- klient zostaje resumed
- callbacki zmieniają zakres
## teleprompter:
SurfaceView utrzymuje granicę renderingu, a klient pozostaje aktywny podczas wyboru.
Callbacki `onUriPermissionGranted` i `onUriPermissionRevoked` pokazują, kiedy zmienia się zakres dostępu.
To jest picker osadzony w aplikacji, ale nadal sterowany przez system.

#slide 95
## layout
bullet
## slide title
Embedded photo picker
## subtitle
Jak pęka
## bullets
- stary URI po revoke
- własna galeria omija picker
- latest selection nie jest respektowane
## teleprompter:
Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke albo buduje własną galerię obok pickera.
Jeśli latest selection nie jest respektowane, osadzony picker traci sens jako kontrolowany wybór.
To już nie jest systemowy flow, tylko obejście obok niego.

#slide 96
## layout
bullet
## slide title
Embedded photo picker
## subtitle
Jak się bronić
## bullets
- picker contract jako jedyny wybór
- odświeżenie po revoke
- brak własnej galerii obok
## teleprompter:
Obrona polega na tym, że embedded picker jest jedyną ścieżką wyboru, a nie dodatkiem do własnej galerii.
Po revoke trzeba odświeżyć stan i usunąć stare URI.
Jeśli aplikacja buduje drugi, równoległy wybór, to systemowa kontrola przestaje działać.

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

#slide 145
## layout
definition
## slide title
Retention vs disposal
## subtitle
Co to jest
## term
Retention vs disposal
## definition
Retencja decyduje o czasie życia danych, a disposal o ich fizycznym zniknięciu.
## teleprompter:
Retencja ustala, jak długo dane mogą istnieć w systemie, a disposal opisuje moment ich faktycznego wycofania z nośnika i z kopii pośrednich. W systemach log-structured zapis i delete nie zamykają jeszcze sprawy, bo zmienia się tylko status logiczny, a stare segmenty, metadane, cache i snapshoty nadal mogą przechowywać treść. Na flashu sytuację komplikuje wear leveling i translacja bloków w FTL, więc fizyczny zapis żyje dłużej niż widok widoczny dla aplikacji. To właśnie dlatego secure deletion musi rozróżniać logikę usunięcia od fizycznego sprzątania.
#slide 146
## layout
bullet
## slide title
Retention vs disposal
## subtitle
Jak działa
## bullets
- Retention vs disposal: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Retention vs disposal: Retencja mówi jak długo dane wolno trzymać a…
- Retention vs disposal: Obrona wymaga polityki retention oddzielonej od disposal testów…
## teleprompter:
Przepływ zaczyna się od zwykłego usunięcia w API albo w systemie plików, ale to jeszcze nie oznacza usunięcia fizycznego. Na nośniku dane mogą czekać w segmentach nieużytych, w metadanych z poprzedniego stanu i w kopiach wykonanych przez synchronizację albo backup. Secure deletion musi więc opisać nie tylko sam delete, lecz także to, kiedy garbage collection wybiera segment do sprzątnięcia, kiedy blok wraca do puli wolnej i czy stara treść znika z warstwy poniżej filesystemu. Bez tego aplikacja widzi tylko zmianę etykiety, nie zmianę zawartości.
#slide 147
## layout
bullet
## slide title
Retention vs disposal
## subtitle
Jak pęka
## bullets
- Retention vs disposal: Atak nie musi łamać szyfrowania wystarczy że odzyska…
- Retention vs disposal: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Retention vs disposal: Retencja mówi jak długo dane wolno trzymać a…
## teleprompter:
Atak wykorzystuje to, że system uznaje dane za usunięte z punktu widzenia aplikacji, choć resztki nadal istnieją. Wystarczy odzyskać stary blok, miniaturę, cache albo kopię pośrednią z backupu. Jeśli w grę wchodzi wersjonowanie albo FTL, przeciwnik nie musi obchodzić szyfrowania, tylko musi znaleźć wcześniejszy zapis albo poprzednią mapę bloków. Z punktu widzenia napastnika najcenniejsze są nie nowe dane, lecz stary stan, którego system jeszcze nie zdążył fizycznie porzucić.
#slide 148
## layout
bullet
## slide title
Retention vs disposal
## subtitle
Jak się bronić
## bullets
- Retention vs disposal: Obrona wymaga polityki retention oddzielonej od disposal testów…
- Retention vs disposal: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Retention vs disposal: Atak nie musi łamać szyfrowania wystarczy że odzyska…
## teleprompter:
Obrona wymaga osobnej polityki retencji i osobnej polityki disposal. Trzeba zdecydować, kiedy dane są jeszcze potrzebne, kiedy mają zniknąć logicznie, a kiedy fizycznie, a potem przypisać te decyzje do konkretnych katalogów, cache i backupów. Po kasowaniu potrzebny jest test odzysku, pomiar kosztu w wear i latency oraz sprawdzenie, czy kopie pośrednie nie zostały poza zasięgiem tej samej reguły. Jeżeli retencja nie obejmuje wszystkich miejsc, w których dane się rozszczepiają, to polityka wygląda dobrze tylko na papierze.
#slide 149
## layout
definition
## slide title
Why delete fails
## subtitle
Co to jest
## term
Why delete fails
## definition
Delete zawodzi przez remanencję danych i metadanych.
## teleprompter:
Delete fails, bo system usuwa nazwę lub wpis katalogowy, a nie zawsze faktyczne bity. Remanencja obejmuje treść, metadane, mapy alokacji, miniatury, dzienniki i fragmenty, które zostały już odłączone od bieżącej ścieżki, ale nie zostały jeszcze fizycznie wyczyszczone. Na flashu stare komórki mogą pozostać osiągalne dla warstwy poniżej filesystemu, a na nośniku z log-structured storage stary zapis może jeszcze czekać na swoje kolejne użycie.
#slide 150
## layout
bullet
## slide title
Why delete fails
## subtitle
Jak działa
## bullets
- Why delete fails: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Why delete fails: Retencja mówi jak długo dane wolno trzymać a…
- Why delete fails: Obrona wymaga polityki retention oddzielonej od disposal testów…
## teleprompter:
Najpierw aplikacja oznacza plik jako usunięty, potem filesystem zwalnia wpis, a dopiero później garbage collector może przenieść lub nadpisać fragmenty danych. W log-structured storage ten krok nie jest natychmiastowy, bo system zapisuje nowe wersje obok starych i tylko później konsoliduje przestrzeń. To dlatego sam moment delete nie daje gwarancji zniknięcia treści, a czas między logicznym i fizycznym usunięciem jest ważną częścią modelu zagrożeń.
#slide 151
## layout
bullet
## slide title
Why delete fails
## subtitle
Jak pęka
## bullets
- Why delete fails: Atak nie musi łamać szyfrowania wystarczy że odzyska…
- Why delete fails: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Why delete fails: Retencja mówi jak długo dane wolno trzymać a…
## teleprompter:
W ataku nie trzeba łamać kryptografii. Wystarczy odzyskać poprzedni blok danych, poprzednią wersję metadanych albo plik tymczasowy, który aplikacja uważała za nietrwały. Jeśli backup albo synchronizacja wykonały dodatkową kopię, usunięcie jednego katalogu niczego nie zmienia poza bieżącym widokiem aplikacji. To dlatego forensic recovery zwykle zaczyna się od szukania resztek poza główną ścieżką, a nie od próby złamania samego szyfrowania.
#slide 152
## layout
bullet
## slide title
Why delete fails
## subtitle
Jak się bronić
## bullets
- Why delete fails: Obrona wymaga polityki retention oddzielonej od disposal testów…
- Why delete fails: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Why delete fails: Atak nie musi łamać szyfrowania wystarczy że odzyska…
## teleprompter:
Obrona polega na tym, że usuwanie jest projektowane tak samo świadomie jak zapis. Trzeba wiedzieć, które kopie istnieją, gdzie są trzymane, jak długo mogą żyć i czy można je odnaleźć po odtworzeniu nośnika. W praktyce potrzebne są testy odzysku, a nie tylko sprawdzenie, czy plik znika z listy. Jeśli po usunięciu da się jeszcze odzyskać miniaturę, fragment logu albo snapshot, to reguła usuwania nie obejmuje całego cyklu życia danych.
#slide 153
## layout
definition
## slide title
Log-structured storage
## subtitle
Co to jest
## term
Log-structured storage
## definition
Log-structured filesystems dopisują nowe bloki i czyszczą stare dopiero później.
## teleprompter:
Log-structured storage dopisuje nowe dane zamiast nadpisywać stare miejsce. To daje dobrą wydajność zapisu i prostsze kolejkowanie zmian, ale tworzy historię starych segmentów, które żyją do momentu sprzątnięcia. Usuwanie nie usuwa natychmiast wszystkich śladów, bo stary zapis pozostaje w blokach, dopóki garbage collection nie uzna ich za zbędne i nie odzyska przestrzeni do ponownego użycia.
#slide 154
## layout
bullet
## slide title
Log-structured storage
## subtitle
Jak działa
## bullets
- Log-structured storage: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Log-structured storage: Retencja mówi jak długo dane wolno trzymać a…
- Log-structured storage: Obrona wymaga polityki retention oddzielonej od disposal testów…
## teleprompter:
Sekwencja pracy jest prosta: najpierw powstaje nowa wersja danych, potem stara wersja traci aktualność, a dopiero później system odzyskuje przestrzeń. W międzyczasie mogą istnieć równolegle segment aktywny i segment już niepotrzebny, a czasem także kilka starszych kopii tego samego fragmentu. To właśnie w tym oknie stare treści są nadal odzyskiwalne, choć z perspektywy aplikacji już dawno „zniknęły”.
#slide 155
## layout
bullet
## slide title
Log-structured storage
## subtitle
Jak pęka
## bullets
- Log-structured storage: Atak nie musi łamać szyfrowania wystarczy że odzyska…
- Log-structured storage: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Log-structured storage: Retencja mówi jak długo dane wolno trzymać a…
## teleprompter:
Przeciwnik wykorzystuje fakt, że stare segmenty nie znikają w chwili zmiany widoku logicznego. Jeśli do tego dołożysz cache, miniatury, dzienniki i kopie w synchronizacji, to recovery dostaje wiele punktów zaczepienia. Atak staje się prosty: znaleźć nieaktualny, ale nadal zapisany stan i odczytać go z warstwy, która jeszcze nie wykonała garbage collection albo nie zwolniła wszystkich bloków.
#slide 156
## layout
bullet
## slide title
Log-structured storage
## subtitle
Jak się bronić
## bullets
- Log-structured storage: Obrona wymaga polityki retention oddzielonej od disposal testów…
- Log-structured storage: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Log-structured storage: Atak nie musi łamać szyfrowania wystarczy że odzyska…
## teleprompter:
Obrona musi uwzględnić cały cykl życia danych, nie tylko nazwę pliku. Trzeba sprawdzić, które katalogi są cache, które są backupem, które są tymczasowe, a które naprawdę można czyścić agresywnie. W log-structured storage bezpieczeństwo kasowania zależy od tego, czy polityka wie o wszystkich miejscach, w których dane się rozszczepiają: pliku głównym, plikach pomocniczych, kopiach generowanych automatycznie i wersjach, które użytkownik już przestał widzieć.
#slide 157
## layout
definition
## slide title
YAFFS example
## subtitle
Co to jest
## term
YAFFS example
## definition
YAFFS na flashu zostawia stare wersje, bo garbage collection nie kasuje wszystkiego od razu.
## teleprompter:
YAFFS pokazuje problem bardzo wprost: system jest projektowany pod flash, więc zapis i kasowanie są rozdzielone przez wear leveling i garbage collection. Stary blok może przeżyć kilka kolejnych zmian widoku logicznego, zanim zostanie fizycznie zwolniony, a kolejne zapisy mogą tylko przesuwać jego zniknięcie w czasie. To czyni każde secure deletion zależnym od zachowania warstwy niższej niż filesystem i od tego, kiedy nośnik faktycznie odzyska blok.
#slide 158
## layout
bullet
## slide title
YAFFS example
## subtitle
Jak działa
## bullets
- YAFFS example: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- YAFFS example: Retencja mówi jak długo dane wolno trzymać a…
- YAFFS example: Obrona wymaga polityki retention oddzielonej od disposal testów…
## teleprompter:
W praktyce aplikacja widzi zwykły delete, ale YAFFS może tylko oznaczyć dane jako nieaktualne i przesunąć prawdziwe czyszczenie na później. Jeżeli w międzyczasie nośnik wykona dodatkowe przeniesienia, odzysk może trafić nie w jeden blok, tylko w kilka historycznych kopii, z których każda ma inną szansę przeżycia garbage collection. To właśnie dlatego laboratoria secure deletion na YAFFS mierzą skuteczność w czasie, a nie tylko w chwili wywołania API.
#slide 159
## layout
bullet
## slide title
YAFFS example
## subtitle
Jak pęka
## bullets
- YAFFS example: Atak nie musi łamać szyfrowania wystarczy że odzyska…
- YAFFS example: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- YAFFS example: Retencja mówi jak długo dane wolno trzymać a…
## teleprompter:
Atak na YAFFS nie musi wyglądać spektakularnie. Wystarczy zrzut nośnika, analiza poprzednich segmentów i szukanie bloków, które po stronie systemu są już wolne, ale nie zostały jeszcze fizycznie wyczyszczone. Jeśli pojawiają się też backupy lub pliki tymczasowe, odzysk staje się jeszcze prostszy, bo napastnik ma kilka ścieżek dojścia do tej samej treści.
#slide 160
## layout
bullet
## slide title
YAFFS example
## subtitle
Jak się bronić
## bullets
- YAFFS example: Obrona wymaga polityki retention oddzielonej od disposal testów…
- YAFFS example: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- YAFFS example: Atak nie musi łamać szyfrowania wystarczy że odzyska…
## teleprompter:
Obrona dla YAFFS musi liczyć się z ceną kasowania. Im agresywniejsze wymazywanie, tym większy wpływ na wear, czas i stabilność zapisu. Sensowne zabezpieczenie wymaga więc polityki, która wie, kiedy warto usunąć natychmiast, a kiedy lepiej przechować dane szyfrowane do czasu naturalnego wygaszenia, bo samo przyspieszenie czyszczenia może zużyć nośnik szybciej niż wynosi zysk bezpieczeństwa.
#slide 161
## layout
definition
## slide title
FTL mapping
## subtitle
Co to jest
## term
FTL mapping
## definition
FTL mapuje logiczne bloki na fizyczne bloki poza kontrolą filesystemu.
## teleprompter:
FTL stoi między filesystemem a fizycznymi komórkami pamięci. System plików mówi „usuń ten blok”, ale FTL może przenieść dane w inne miejsce, zostawiając poprzedni zapis jako resztkę do późniejszego garbage collection. To dlatego logiczny adres nie odpowiada jednemu, stałemu fizycznemu blokowi, a jeden plik może przejść przez kilka fizycznych lokacji zanim zniknie na dobre.
#slide 162
## layout
bullet
## slide title
FTL mapping
## subtitle
Jak działa
## bullets
- FTL mapping: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- FTL mapping: Retencja mówi jak długo dane wolno trzymać a…
- FTL mapping: Obrona wymaga polityki retention oddzielonej od disposal testów…
## teleprompter:
Gdy aplikacja nadpisuje rekord albo usuwa plik, FTL może zmapować nowy zapis do świeżego miejsca, a stary blok zostawić do sprzątnięcia później. W efekcie w urządzeniu powstają dwie warstwy prawdy: ta widoczna dla systemu i ta istniejąca fizycznie do czasu wewnętrznego porządkowania. Ta druga jest ważna dla secure deletion, bo właśnie tam mogą zostawać resztki danych, mimo że filesystem uważa operację za zakończoną.
#slide 163
## layout
bullet
## slide title
FTL mapping
## subtitle
Jak pęka
## bullets
- FTL mapping: Atak nie musi łamać szyfrowania wystarczy że odzyska…
- FTL mapping: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- FTL mapping: Retencja mówi jak długo dane wolno trzymać a…
## teleprompter:
Przeciwnik wykorzystuje tę różnicę, gdy szuka starego układu bloków na nośniku. Nadpisanie logiczne nie oznacza nadpisania dokładnie tego samego miejsca na kościach flash, więc poprzedni zapis może czekać na skasowanie w innym fizycznym sektorze. Jeżeli do tego dojdą snapshoty albo cache, odzysk z poziomu niższego niż filesystem staje się realny i nie wymaga żadnej sztuczki z kryptografią.
#slide 164
## layout
bullet
## slide title
FTL mapping
## subtitle
Jak się bronić
## bullets
- FTL mapping: Obrona wymaga polityki retention oddzielonej od disposal testów…
- FTL mapping: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- FTL mapping: Atak nie musi łamać szyfrowania wystarczy że odzyska…
## teleprompter:
Obrona przeciw FTL nie polega na samym delete. Potrzebne są procedury, które wiedzą, kiedy fizyczne wyczyszczenie jest naprawdę zakończone, a kiedy system tylko oddał blok do ponownego użycia. Bez takiej wiedzy secure deletion jest tylko deklaracją z poziomu API, a nie stanem, który da się obronić przy odzysku nośnika.
#slide 165
## layout
definition
## slide title
Overwrite problem
## subtitle
Co to jest
## term
Overwrite problem
## definition
Overwrite nie daje gwarancji, że nadpiszesz dokładnie ten fizyczny blok, który chcesz usunąć.
## teleprompter:
Overwrite problem polega na tym, że program myśli w kategoriach pliku, a nośnik pracuje w kategoriach bloków i stron. W log-structured lub flashowym systemie plików nadpisanie może trafić w nowy blok, a stary pozostać nienaruszony, bo warstwa pośrednia wybiera sobie świeże miejsce zamiast przepisać poprzedni adres. Samo „wpisanie zera” nie daje więc gwarancji fizycznego wymazania.
#slide 166
## layout
bullet
## slide title
Overwrite problem
## subtitle
Jak działa
## bullets
- Overwrite problem: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Overwrite problem: Retencja mówi jak długo dane wolno trzymać a…
- Overwrite problem: Obrona wymaga polityki retention oddzielonej od disposal testów…
## teleprompter:
Przebieg jest podstępny: system zapisuje nową wersję w nowym miejscu, katalog wskazuje już na świeży rekord, a stary rekord nadal leży w tle. To oznacza, że przy kasowaniu trzeba patrzeć nie tylko na widok logiczny, ale też na ścieżkę migracji danych przez warstwę pośrednią, bo dopiero ona decyduje, gdzie znajdzie się poprzednia treść.
#slide 167
## layout
bullet
## slide title
Overwrite problem
## subtitle
Jak pęka
## bullets
- Overwrite problem: Atak nie musi łamać szyfrowania wystarczy że odzyska…
- Overwrite problem: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Overwrite problem: Retencja mówi jak długo dane wolno trzymać a…
## teleprompter:
Atak polega na tym, że ktoś czyta stary blok, do którego filesystem przestał się odwoływać, ale który wciąż istnieje fizycznie. Gdy do tego dołożysz logi, cache, miniatury i kopie synchronizowane, skala resztek rośnie bardzo szybko. Wtedy overwrite okazuje się tylko zmianą referencji, nie czyszczeniem nośnika, a recovery może zacząć od dowolnej z tych pozostałości.
#slide 168
## layout
bullet
## slide title
Overwrite problem
## subtitle
Jak się bronić
## bullets
- Overwrite problem: Obrona wymaga polityki retention oddzielonej od disposal testów…
- Overwrite problem: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Overwrite problem: Atak nie musi łamać szyfrowania wystarczy że odzyska…
## teleprompter:
Obrona wymaga sprawdzenia, że wymazanie nie kończy się tylko na logicznym update katalogu. Trzeba wykonać test odzysku, porównać zachowanie na różnych nośnikach i odnieść koszt do oczekiwanej skuteczności. Jeśli nośnik jest flashowy, najważniejsze jest to, co dzieje się poniżej warstwy plików: mapowanie, przenoszenie bloków i moment, w którym stare dane naprawdę znikają.
#slide 169
## layout
definition
## slide title
Encryption limitation
## subtitle
Co to jest
## term
Encryption limitation
## definition
Sama kryptografia nie pomaga, jeśli stare kopie lub klucze nadal są dostępne.
## teleprompter:
Szyfrowanie nie rozwiązuje problemu kasowania, jeśli stare kopie i stare klucze nadal istnieją. Dane mogą być zaszyfrowane, a mimo to nadal obecne w innych blokach, w snapshotach albo w backupie. Secure deletion musi więc objąć zarówno treść, jak i ślady po niej, bo usunięcie jednego klucza nie kasuje drugiej, aktywnej kopii.
#slide 170
## layout
bullet
## slide title
Encryption limitation
## subtitle
Jak działa
## bullets
- Encryption limitation: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Encryption limitation: Retencja mówi jak długo dane wolno trzymać a…
- Encryption limitation: Obrona wymaga polityki retention oddzielonej od disposal testów…
## teleprompter:
W praktyce przebieg wygląda tak: aplikacja usuwa rekord, filesystem zwalnia miejsce logicznie, ale fizyczna kopia zostaje, dopóki system jej nie porzuci. Jeżeli backup albo cache mają własne cykle życia, klucz szyfrujący też nie wystarcza, bo kopia nadal może zostać odtworzona z innego miejsca, często nawet bez dostępu do głównego pliku.
#slide 171
## layout
bullet
## slide title
Encryption limitation
## subtitle
Jak pęka
## bullets
- Encryption limitation: Atak nie musi łamać szyfrowania wystarczy że odzyska…
- Encryption limitation: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Encryption limitation: Retencja mówi jak długo dane wolno trzymać a…
## teleprompter:
Atak na „same encryption” zwykle polega na odzyskaniu starszej wersji zaszyfrowanego pliku albo odtworzeniu klucza z miejsca, które nie zostało wyczyszczone. Jeśli zniknie tylko jedna ścieżka, a zostanie druga, dane pozostają dostępne. To dlatego szyfrowanie jest ochroną poufności, ale nie automatycznie usuwaniem, i dlatego same zmiany klucza nie wystarczają bez fizycznego wymazania artefaktów.
#slide 172
## layout
bullet
## slide title
Encryption limitation
## subtitle
Jak się bronić
## bullets
- Encryption limitation: Obrona wymaga polityki retention oddzielonej od disposal testów…
- Encryption limitation: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Encryption limitation: Atak nie musi łamać szyfrowania wystarczy że odzyska…
## teleprompter:
Obrona musi połączyć usuwanie treści z usuwaniem śladów operacyjnych. Trzeba wiedzieć, gdzie są kopie, jak długo żyją i co robi system po zmianie kluczy. Bez tego szyfrowanie daje fałszywe poczucie zakończenia, mimo że fizyczne resztki nadal są obecne w cache, backupie albo w starej wersji nośnika.
#slide 173
## layout
definition
## slide title
Purge algorithm
## subtitle
Co to jest
## term
Purge algorithm
## definition
Purge chce realnie zniszczyć lub przenieść dane aż recovery przestaje być praktyczne.
## teleprompter:
Purge algorithm ma doprowadzić nośnik do stanu, w którym odzysk przestaje być praktyczny. To oznacza albo fizyczne zniszczenie danych, albo takie przeniesienie i nadpisanie bloków, żeby nie dało się już odtworzyć spójnej treści z więcej niż jednego źródła. W badaniach nad secure deletion purge jest najbliżej twardego wymazywania, bo celuje w usunięcie samego materiału, nie tylko jego referencji.
#slide 174
## layout
bullet
## slide title
Purge algorithm
## subtitle
Jak działa
## bullets
- Purge algorithm: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Purge algorithm: Retencja mówi jak długo dane wolno trzymać a…
- Purge algorithm: Obrona wymaga polityki retention oddzielonej od disposal testów…
## teleprompter:
Krok purge polega na identyfikacji bloków, ich przeniesieniu lub oznaczeniu do zniszczenia i doprowadzeniu garbage collection do faktycznego oczyszczenia. W log-structured storage ten proces trwa, bo system nie usuwa bloków natychmiast, tylko przesuwa je między aktywną a nieaktywną częścią przestrzeni. Dopiero gdy kopie znikną z aktywnego obiegu i nie da się ich już odczytać spod warstwy logicznej, można mówić o realnym kasowaniu.
#slide 175
## layout
bullet
## slide title
Purge algorithm
## subtitle
Jak pęka
## bullets
- Purge algorithm: Atak nie musi łamać szyfrowania wystarczy że odzyska…
- Purge algorithm: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Purge algorithm: Retencja mówi jak długo dane wolno trzymać a…
## teleprompter:
Przeciwnik szuka momentu, w którym purge jeszcze nie skończył sprzątania. Jeśli stary blok pozostaje poza aktywnym widokiem, ale nie został fizycznie wymazany, odzysk nadal jest możliwy. Zewnętrzny backup albo cache tylko zwiększa liczbę miejsc, które trzeba oczyścić, a każdy dodatkowy punkt kopii przesuwa moment pełnego bezpieczeństwa.
#slide 176
## layout
bullet
## slide title
Purge algorithm
## subtitle
Jak się bronić
## bullets
- Purge algorithm: Obrona wymaga polityki retention oddzielonej od disposal testów…
- Purge algorithm: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Purge algorithm: Atak nie musi łamać szyfrowania wystarczy że odzyska…
## teleprompter:
Obrona przy purge wymaga sprawdzenia, czy system naprawdę doprowadził sprzątanie do końca. Sama deklaracja usunięcia nie wystarcza, potrzebny jest test po czasie i na różnych warstwach nośnika. To szczególnie ważne tam, gdzie garbage collection działa w tle i nie kończy się w chwili wywołania API, bo wtedy poprawny wynik można zobaczyć dopiero po pewnym opóźnieniu.
#slide 177
## layout
definition
## slide title
Ballooning algorithm
## subtitle
Co to jest
## term
Ballooning algorithm
## definition
Ballooning zjada wolne miejsce, by wymusić wypchnięcie bloku celu.
## teleprompter:
Ballooning to metoda wymuszania sprzątania przez zjadanie wolnego miejsca. System wypełnia pamięć dodatkowymi zapisami, aż nośnik musi wyrzucić wcześniejszy blok albo go przenieść. Dzięki temu można zmusić warstwę pod spodem do pracy nad usunięciem wskazanego fragmentu, zamiast polegać na tym, że zrobi to sama „przy okazji”.
#slide 178
## layout
bullet
## slide title
Ballooning algorithm
## subtitle
Jak działa
## bullets
- Ballooning algorithm: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Ballooning algorithm: Retencja mówi jak długo dane wolno trzymać a…
- Ballooning algorithm: Obrona wymaga polityki retention oddzielonej od disposal testów…
## teleprompter:
Przebieg ballooningu jest pośredni: najpierw pojawiają się sztuczne zapisy, potem rośnie presja na garbage collection, a na końcu blok celu zostaje wypchnięty lub zastąpiony. To nie jest jednorazowe „usuń”, tylko kontrolowane zatkanie przestrzeni, żeby system sam wykonał fizyczne sprzątanie. W praktyce trzeba obserwować, czy wypchnięty blok nie wróci później jako odzyskiwalna resztka.
#slide 179
## layout
bullet
## slide title
Ballooning algorithm
## subtitle
Jak pęka
## bullets
- Ballooning algorithm: Atak nie musi łamać szyfrowania wystarczy że odzyska…
- Ballooning algorithm: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Ballooning algorithm: Retencja mówi jak długo dane wolno trzymać a…
## teleprompter:
Atak na ballooning wykorzystuje moment, w którym presja jeszcze nie doprowadziła do pełnego wyczyszczenia. Jeżeli stare segmenty nadal istnieją, a kolejne zapisy tylko przesuwają granicę, odzysk może się udać z wcześniejszej wersji nośnika. Im więcej kopii pośrednich, tym większa szansa, że jedna z nich przetrwa i da się ją odtworzyć z innego miejsca niż bieżący rekord.
#slide 180
## layout
bullet
## slide title
Ballooning algorithm
## subtitle
Jak się bronić
## bullets
- Ballooning algorithm: Obrona wymaga polityki retention oddzielonej od disposal testów…
- Ballooning algorithm: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Ballooning algorithm: Atak nie musi łamać szyfrowania wystarczy że odzyska…
## teleprompter:
Obrona musi weryfikować, czy ballooning faktycznie wymusił likwidację celu, a nie tylko zajęcie dodatkowego miejsca. Jeśli test pokazuje stale odzyskiwalne fragmenty, metoda nie spełnia swojej roli. Do sensownego użycia potrzebne są też limity kosztu, bo zbyt agresywne zjadanie miejsca wpływa na wydajność całego urządzenia, skraca życie flasha i może odbić się na innych danych.
#slide 181
## layout
definition
## slide title
Zero overwriting
## subtitle
Co to jest
## term
Zero overwriting
## definition
Zero overwriting wypełnia obszar i potem vacuumuje resztki.
## teleprompter:
Zero overwriting polega na wypełnieniu obszaru kontrolowanym wzorcem, a potem wymuszeniu vacuumingu i usunięcia resztek. Celem jest wypchnięcie starych danych tak, żeby nie zostały w aktywnym obiegu ani w łatwo dostępnej kopii. Ta technika próbuje zbliżyć się do fizycznego wymazania bez prostego nadpisania jednego adresu, co ma znaczenie na nośnikach, gdzie jeden blok może mieć kilka pokoleń zapisów.
#slide 182
## layout
bullet
## slide title
Zero overwriting
## subtitle
Jak działa
## bullets
- Zero overwriting: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Zero overwriting: Retencja mówi jak długo dane wolno trzymać a…
- Zero overwriting: Obrona wymaga polityki retention oddzielonej od disposal testów…
## teleprompter:
Przebieg wymaga zwykle kilku kroków: najpierw zapis wypełniający, potem odczyt i porównanie, potem czyszczenie resztek i sprawdzenie, czy nośnik oddał miejsce do ponownego użycia. W systemie flash liczy się jednak to, czy pod spodem nie zostały nadal stare komórki, które nie weszły jeszcze do obiegu, albo czy vacuuming nie zostawił śladów w warstwie pośredniej.
#slide 183
## layout
bullet
## slide title
Zero overwriting
## subtitle
Jak pęka
## bullets
- Zero overwriting: Atak nie musi łamać szyfrowania wystarczy że odzyska…
- Zero overwriting: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Zero overwriting: Retencja mówi jak długo dane wolno trzymać a…
## teleprompter:
Atak na zero overwriting wykorzystuje to, że czyszczenie może nie objąć wszystkich warstw naraz. Jeżeli część danych została przeniesiona w trakcie porządkowania, a część czeka jeszcze na garbage collection, odzysk może nastąpić z kilku chwilowych stanów naraz. Wtedy samo wypełnienie nie daje pełnej gwarancji, bo odzyskiwalny może być nie tylko końcowy stan, ale też jeden z pośrednich.
#slide 184
## layout
bullet
## slide title
Zero overwriting
## subtitle
Jak się bronić
## bullets
- Zero overwriting: Obrona wymaga polityki retention oddzielonej od disposal testów…
- Zero overwriting: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Zero overwriting: Atak nie musi łamać szyfrowania wystarczy że odzyska…
## teleprompter:
Obrona wymaga nie tylko techniki, ale i dowodu skuteczności. Trzeba sprawdzić, czy po całym cyklu nie da się już odzyskać sensownej treści, oraz policzyć koszt operacji w zużyciu nośnika i czasie. Jeśli testy pokazują resztki, technika nie jest jeszcze bezpieczna dla tego konkretnego nośnika, nawet jeśli wygląda dobrze na poziomie logicznego API.
#slide 185
## layout
definition
## slide title
Versioned file system
## subtitle
Co to jest
## term
Versioned file system
## definition
Snapshoty i historia wersji komplikują kasowanie, bo stare stany nadal istnieją.
## teleprompter:
Wersjonowany filesystem zachowuje historię zmian, więc stare stany istnieją obok nowego. Snapshoty i gałęzie dają wygodę odtwarzania, ale komplikują kasowanie, bo usunięcie bieżącej wersji nie usuwa automatycznie poprzednich. Z punktu widzenia bezpieczeństwa taki system jest jednocześnie magazynem historii i magazynem danych, które użytkownik już uznał za usunięte.
#slide 186
## layout
bullet
## slide title
Versioned file system
## subtitle
Jak działa
## bullets
- Versioned file system: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Versioned file system: Retencja mówi jak długo dane wolno trzymać a…
- Versioned file system: Obrona wymaga polityki retention oddzielonej od disposal testów…
## teleprompter:
Przebieg w systemie wersjonowanym jest taki, że nowe dane trafiają do aktualnego widoku, a stare wersje pozostają pod spodem jako punkty przywracania. Jeżeli nie ma osobnego procesu usuwania historii, delete dotyka tylko bieżącej gałęzi. W praktyce trzeba więc czyścić także to, co użytkownik już przestał widzieć, bo właśnie tam często zostaje pełna treść, nie tylko różnica między wersjami.
#slide 187
## layout
bullet
## slide title
Versioned file system
## subtitle
Jak pęka
## bullets
- Versioned file system: Atak nie musi łamać szyfrowania wystarczy że odzyska…
- Versioned file system: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Versioned file system: Retencja mówi jak długo dane wolno trzymać a…
## teleprompter:
Atak na system wersjonowany jest prosty: odzyskuje się poprzedni snapshot, nieaktualną gałąź albo stare metadane. Jeśli aplikacja lub backup zatrzymały wcześniejszą wersję, osoba atakująca nie potrzebuje łamać bieżącej kopii. Wystarczy sięgnąć po historię, którą system nadal przechowuje, albo po wersję pomocniczą, którą sam użytkownik przestał śledzić.
#slide 188
## layout
bullet
## slide title
Versioned file system
## subtitle
Jak się bronić
## bullets
- Versioned file system: Obrona wymaga polityki retention oddzielonej od disposal testów…
- Versioned file system: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Versioned file system: Atak nie musi łamać szyfrowania wystarczy że odzyska…
## teleprompter:
Obrona wymaga polityki, która wie, które wersje są potrzebne, a które muszą zniknąć naprawdę. To oznacza osobne zarządzanie historią, testy odzysku i kontrolę, czy stare wersje nie przetrwają w miejscach pomocniczych, w snapshotach systemowych albo w kopiach generowanych przy synchronizacji. Bez tego wersjonowanie staje się ukrytą kopią zapasową.
#slide 189
## layout
definition
## slide title
Forensic verification
## subtitle
Co to jest
## term
Forensic verification
## definition
Forensic verification sprawdza, czy po usunięciu da się jeszcze odzyskać treść lub jej ślady.
## teleprompter:
Forensic verification sprawdza, czy po wymazaniu można jeszcze odzyskać treść albo jej ślady. To nie jest ocena deklaracji, tylko praktyczny test na nośniku, segmentach, metadanych i artefaktach pośrednich. Jeśli odzysk działa, secure deletion nie zadziałało w tej konfiguracji, nawet jeśli aplikacja już dawno uważa dane za usunięte.
#slide 190
## layout
bullet
## slide title
Forensic verification
## subtitle
Jak działa
## bullets
- Forensic verification: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Forensic verification: Retencja mówi jak długo dane wolno trzymać a…
- Forensic verification: Obrona wymaga polityki retention oddzielonej od disposal testów…
## teleprompter:
Przebieg takiego sprawdzenia zwykle obejmuje próbę odczytu pozostałości po delete, analizę metadanych, badanie snapshotów i porównanie wyniku z oczekiwaniem. Na flashu trzeba dodatkowo uwzględnić czas pracy garbage collection, bo resztki nie zawsze znikają od razu. To test, który musi uwzględnić opóźnienie, a nie tylko chwilę wywołania, bo wynik może się zmieniać dopiero po sprzątnięciu w tle.
#slide 191
## layout
bullet
## slide title
Forensic verification
## subtitle
Jak pęka
## bullets
- Forensic verification: Atak nie musi łamać szyfrowania wystarczy że odzyska…
- Forensic verification: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Forensic verification: Retencja mówi jak długo dane wolno trzymać a…
## teleprompter:
Atak w tym obszarze polega na tym, że ktoś korzysta z okna, w którym resztki jeszcze istnieją. Nie trzeba łamać szyfrowania, jeśli da się odzyskać blok, kopię pośrednią albo wersję ze snapshotu. Weryfikacja kryminalistyczna właśnie po to istnieje, żeby ten stan wykryć i pokazać, że fizyczne usunięcie nie nadążyło za logicznym.
#slide 192
## layout
bullet
## slide title
Forensic verification
## subtitle
Jak się bronić
## bullets
- Forensic verification: Obrona wymaga polityki retention oddzielonej od disposal testów…
- Forensic verification: W log-structured filesystems delete zwykle oznacza tylko oznaczenie…
- Forensic verification: Atak nie musi łamać szyfrowania wystarczy że odzyska…
## teleprompter:
Obrona wymaga testów po czasie i na realnym nośniku, nie tylko w emulatorze czy na pustym katalogu. Trzeba potwierdzić, że po całym cyklu nie ma już sensownej treści do odzyskania i że koszt takiego usuwania jest akceptowalny. Bez tego każda deklaracja secure deletion pozostaje tylko deklaracją, a nie zweryfikowaną właściwością systemu.

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
