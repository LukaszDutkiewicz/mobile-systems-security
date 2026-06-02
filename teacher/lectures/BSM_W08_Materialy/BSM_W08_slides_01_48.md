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