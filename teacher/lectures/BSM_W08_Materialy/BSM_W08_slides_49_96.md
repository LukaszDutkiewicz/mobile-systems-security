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
