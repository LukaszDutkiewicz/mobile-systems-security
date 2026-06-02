from __future__ import annotations

from pathlib import Path


OUT_DIR = Path("/Volumes/Macintosh HD2/Downloads/autotasks/bsm/teacher/lectures/BSM_W08_Materialy")


ASPECTS = [
    (
        "Co to jest",
        "definition",
        "Najpierw zdefiniuj mechanizm i jego granicę. Potem pokaż, co dokładnie znaczy w systemie mobilnym i dlaczego w ogóle istnieje.",
    ),
    (
        "Jak działa",
        "bullet",
        "Tu idź po kolei: wejście, decyzja systemu, stan pośredni, wynik. Nie skracaj przepływu do jednego zdania.",
    ),
    (
        "Jak pęka",
        "bullet",
        "To jest slajd o błędzie i exploit path. Pokaż, gdzie atakujący zyskuje kontrolę i który element jest ufany za dużo.",
    ),
    (
        "Jak się bronić",
        "bullet",
        "Reguła, miejsce egzekwowania, wyjątki, wersja systemu i test regresyjny.",
    ),
]


BLOCKS = [
    {
        "file": "BSM_W08_slides_01_48.md",
        "title": "Lokalna sieć i discovery",
        "lead": "mDNS, SSDP i link-local IPv6 pokazują, że sama obecność w LAN daje aplikacji bardzo dużo informacji o pobliskich usługach i urządzeniach.",
        "mechanics": "mDNS używa rekordów PTR, SRV i TXT na UDP 5353. SSDP używa M-SEARCH i NOTIFY z nagłówkiem LOCATION. Link-local IPv6 działa tylko w obrębie jednego segmentu i używa zakresu fe80::/10. Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby zobaczyć, które sockety, biblioteki i WebView naprawdę korzystają z LAN, a Android 17 ma ten dostęp blokować domyślnie dla targetSdk 37+.",
        "attack": "Spoofing odpowiedzi, korelacja broadcastów i akceptowanie lokalnych rekordów bez własnej walidacji wystarczają, żeby wyjąć nazwę hosta, typ usługi, punkt końcowy albo logiczny identyfikator urządzenia. Gdy aplikacja używa raw socketów albo NsdManager, błąd często kończy się timeoutem TCP, EPERM dla UDP albo błędnym rozpoznaniem usługi.",
        "defense": "LAN powinien być odcięty od Internetu na poziomie polityki, a broad access ma sens tylko wtedy, gdy aplikacja naprawdę potrzebuje discovery. W praktyce oznacza to deklarację NEARBY_WIFI_DEVICES albo ACCESS_LOCAL_NETWORK, testy z adb compat toggle i użycie android_getnetworkblockedreason(int sockFd) po stronie NDK.",
        "subtopics": {
            "mDNS record anatomy": "mDNS ogłasza usługi w LAN przez rekordy PTR, SRV i TXT wysyłane na UDP 5353.",
            "SSDP discovery": "SSDP wykrywa urządzenia przez M-SEARCH, NOTIFY i nagłówek LOCATION.",
            "IPv6 link-local": "IPv6 link-local działa tylko na jednej karcie sieciowej i używa zakresu fe80::/10.",
            "Raw socket access": "Surowe sockety pozwalają aplikacji próbować mDNS i SSDP nawet wtedy, gdy ma tylko INTERNET.",
            "NsdManager": "NsdManager jest frameworkowym API do discovery, które odciąża aplikację od ręcznego skanowania LAN.",
            "Casting path": "Casting zwykle powinien iść przez systemowy picker lub output switcher zamiast przez własne skanowanie usług.",
            "Android 16 opt-in": "Android 16 pozwala developersko włączyć RESTRICT_LOCAL_NETWORK, żeby ujawnić ukryte zależności od LAN.",
            "Android 17 enforcement": "Android 17 blokuje LAN domyślnie dla targetSdk 37+ i wprowadza ACCESS_LOCAL_NETWORK.",
            "Permission split": "Przejście zaczyna się jeszcze przez NEARBY_WIFI_DEVICES, a docelowo trafia do NEARBY_DEVICES.",
            "Broad access path": "Broad access path to klasyczny runtime permission request dla lokalnej sieci.",
            "Privacy-preserving picker": "System-mediated discovery pozwala uniknąć szerokiego grantu dla sieci lokalnej.",
            "Host app inheritance": "WebView dziedziczy stan dostępu do lokalnej sieci po aplikacji hosta.",
        },
    },
    {
        "file": "BSM_W08_slides_49_96.md",
        "title": "Selected media i photo picker",
        "lead": "Zdjęcia i filmy są osobną klasą danych, a nowy model dostępu ma ograniczać aplikacji widzenie całej biblioteki, gdy wystarczy wybrany zestaw URI.",
        "mechanics": "Android 14 wprowadza READ_MEDIA_VISUAL_USER_SELECTED jako dostęp do wybranych zdjęć i filmów, a systemowy picker zwraca content URI bez proszenia o pełen storage access. Embedded photo picker działa w SurfaceView przez setChildSurfacePackage, klient pozostaje w stanie resumed, a callbacki onUriPermissionGranted i onUriPermissionRevoked pokazują, kiedy zakres dostępu się zmienia. Cloud media providers rozszerzają wybór o biblioteki zdalne, a MediaStore#getVersion() ma być przycięty tak, by nie służył jako fingerprint aplikacji.",
        "attack": "Breach pojawia się wtedy, gdy aplikacja trzyma stare URI po revoke, myli partial access z pełnym dostępem, cache'uje wybór bez odświeżenia albo czyta metadane lokalizacji z ACCESS_MEDIA_LOCATION tak, jakby były neutralne. Drugim błędem jest własna galeria, która ignoruje latest selection only i nie synchronizuje selekcji z systemem.",
        "defense": "Obrona wymaga jawnego rozdzielenia permission matrix, odświeżania stanu po revocation, korzystania z picker contract zamiast własnego storage flow oraz ograniczenia wycieku EXIF i lokalizacji. Jeśli aplikacja wspiera starsze urządzenia, backport przez androidx.activity musi zachować ten sam model selekcji, a nie pełny dostęp do biblioteki.",
        "subtopics": {
            "Media as data class": "Zdjęcia i filmy są traktowane jako osobna klasa prywatnych danych.",
            "Selected Photos Access": "Android 14 może dać dostęp tylko do zdjęć i filmów wybranych przez użytkownika.",
            "READ_MEDIA_VISUAL_USER_SELECTED": "READ_MEDIA_VISUAL_USER_SELECTED oznacza partial access do wybranych mediów wizualnych.",
            "Compatibility mode": "Legacy app może działać w trybie kompatybilności, w którym system chroni wybrany podzbiór mediów.",
            "Permission matrix": "Obrazy, filmy i metadane lokalizacji mają różne ścieżki uprawnień i ekspozycji.",
            "Latest selection only": "Latest-selection query zwraca tylko najbardziej aktualny wybrany zestaw URI.",
            "Upgrade behavior": "Upgrade behavior decyduje, czy wcześniej zainstalowana aplikacja zachowa dostęp, czy ma go przeliczyć od nowa.",
            "Photo picker contract": "Systemowy photo picker zwraca content URI bez proszenia o szeroki dostęp do storage.",
            "Backport path": "Jetpack potrafi zbackportować picker na starsze urządzenia przez jeden kontrakt API.",
            "Cloud media providers": "Cloud media providers pozwalają widzieć lokalne i zdalne biblioteki w jednym wyborze.",
            "MediaStore version lockdown": "MediaStore#getVersion() jest przycięty tak, by nie służył jako stabilny fingerprint aplikacji.",
            "Embedded photo picker": "Embedded photo picker działa w SurfaceView przez setChildSurfacePackage i trzyma klienta w stanie resumed.",
        },
    },
    {
        "file": "BSM_W08_slides_97_144.md",
        "title": "Dynamic code loading",
        "lead": "Dynamiczne ładowanie kodu jest potrzebne do pluginów i aktualizacji, ale robi się niebezpieczne, gdy kod można podmienić, uszkodzić albo pobrać z niewiarygodnego źródła.",
        "mechanics": "Oficjalny dokument Androida mówi wprost, żeby unikać dynamic code loading z remote sources, a jeśli kod ma być ładowany, to powinien trafić do internal storage albo scoped storage. Zanim aplikacja wykona taki plik, musi porównać digest albo podpis z zaufaną referencją, a sam plik powinien być traktowany jako artefakt read-only. Ryzyko obejmuje zarówno Dex/Java code, jak i natywny path przez biblioteki współdzielone.",
        "attack": "Atak pojawia się w momencie, gdy ktoś podmieni payload przed verify, dopisze kod do katalogu współdzielonego albo podmieni cały plik z modułem po stronie storage. Jeśli aplikacja pobiera kod z internetu bez kontroli pochodzenia, przeciwnik może skończyć z code execution, exfiltration albo z usunięciem funkcji aplikacji.",
        "defense": "Obrona wymaga verify-before-load, sprawdzenia trusted sources, odrzucenia pliku po niezgodnym hash albo podpisie i trzymania referencji do kontroli integralności poza katalogiem z samym payloadem. Jeśli moduł ma być aktualizowany, trzeba mieć rollback, audit log i testy podmiany pliku, uszkodzonego digestu oraz braków w uprawnieniach do odczytu.",
        "subtopics": {
            "Why DCL exists": "DCL istnieje po to, by obsłużyć modularność, pluginy i runtime updates.",
            "Attack surface": "Powierzchnia ataku rośnie w chwili, gdy ładowany kod da się podmienić lub uszkodzić.",
            "Remote source risk": "Remote code loading jest najdroższe z punktu widzenia ryzyka i może łamać Google Play policy.",
            "Trusted storage": "Kod, który ma być później ładowany, powinien lądować w internal storage albo w scoped storage.",
            "External storage risk": "Shared external storage jest mutowalny, więc nie nadaje się na artefakt wykonywalny.",
            "Integrity before load": "Bezpieczny wzorzec to verify-before-load, a nie load-first.",
            "SHA-256 checker": "SHA-256 checker liczy digest i porównuje go z referencją zaufaną przez aplikację.",
            "Code signing": "Podpis kodu dodaje podpis kryptograficzny i zaufany public key.",
            "Hash storage": "Referencja hash lub signature musi leżeć w chronionym miejscu, a nie obok samego payloadu.",
            "Path to execution": "Niebezpieczna ścieżka to download, write, verify, load i execute.",
            "Class loader choices": "DexClassLoader, PathClassLoader i InMemoryDexClassLoader różnią się tym, skąd biorą kod i jak długo go trzymają.",
            "Native versus Java": "Natywne dlopen i dlsym mają ten sam problem z podmianą co loading pliku dex.",
        },
    },
    {
        "file": "BSM_W08_slides_145_192.md",
        "title": "Retencja i secure deletion",
        "lead": "Retencja mówi, jak długo dane wolno trzymać, a secure deletion próbuje sprawić, by po usunięciu nie dało się ich odzyskać z nośnika.",
        "mechanics": "W log-structured filesystems delete zwykle oznacza tylko oznaczenie danych jako wolnych, a nie fizyczne zniknięcie. YAFFS i podobne systemy na flashu muszą żyć z wear leveling, garbage collection i translacją bloków przez FTL, więc stare wersje danych potrafią zostać w nośniku dłużej niż aplikacja zakłada. Badania nad secure deletion pokazują trzy klasy mechanizmów: purging, ballooning i zero overwriting.",
        "attack": "Atak nie musi łamać szyfrowania, wystarczy że odzyska stare bloki, metadane, miniatury, cache albo kopie pośrednie po synchronizacji i backupie. W systemach wersjonowanych stare snapshoty potrafią przechowywać treść jeszcze długo po logice delete, a forensic scan nadal znajduje resztki.",
        "defense": "Obrona wymaga polityki retention oddzielonej od disposal, testów odzysku po kasowaniu, dobrania metody usuwania do nośnika i kontroli kosztu w wear, latency oraz space. Jeśli aplikacja trzyma cache lub backup, trzeba je uwzględnić osobno, bo secure deletion jednego katalogu nie czyści całego cyklu życia danych.",
        "subtopics": {
            "Retention vs disposal": "Retencja decyduje o czasie życia danych, a disposal o ich fizycznym zniknięciu.",
            "Why delete fails": "Delete zawodzi przez remanencję danych i metadanych.",
            "Log-structured storage": "Log-structured filesystems dopisują nowe bloki i czyszczą stare dopiero później.",
            "YAFFS example": "YAFFS na flashu zostawia stare wersje, bo garbage collection nie kasuje wszystkiego od razu.",
            "FTL mapping": "FTL mapuje logiczne bloki na fizyczne bloki poza kontrolą filesystemu.",
            "Overwrite problem": "Overwrite nie daje gwarancji, że nadpiszesz dokładnie ten fizyczny blok, który chcesz usunąć.",
            "Encryption limitation": "Sama kryptografia nie pomaga, jeśli stare kopie lub klucze nadal są dostępne.",
            "Purge algorithm": "Purge chce realnie zniszczyć lub przenieść dane aż recovery przestaje być praktyczne.",
            "Ballooning algorithm": "Ballooning zjada wolne miejsce, by wymusić wypchnięcie bloku celu.",
            "Zero overwriting": "Zero overwriting wypełnia obszar i potem vacuumuje resztki.",
            "Versioned file system": "Snapshoty i historia wersji komplikują kasowanie, bo stare stany nadal istnieją.",
            "Forensic verification": "Forensic verification sprawdza, czy po usunięciu da się jeszcze odzyskać treść lub jej ślady.",
        },
    },
    {
        "file": "BSM_W08_slides_193_240.md",
        "title": "Apple continuity i cross-device services",
        "lead": "Continuity w ekosystemie Apple to Handoff, Universal Clipboard i Wi-Fi Password Sharing działające przez BLE, AWDL i Wi-Fi.",
        "mechanics": "Prace o Continuity pokazują, że Handoff, Universal Clipboard i Wi-Fi Password Sharing mają własne discovery, transfer i auth state machine, a analiza zwykle opiera się na reverse engineering i packet capture z macOS. Handoff zaczyna się od BLE discovery, AirDrop używa BLE, AWDL i Wi-Fi, a PrivateDrop wymienia kruche contact checks na PSI, żeby nie ujawniać phone numbers ani email addresses.",
        "attack": "Badania wskazują na leakage of identifying information, trackability, spoofing, relay i DoS na warstwie discovery i transportu. W BLE Continuity można odczytać zachowania użytkownika, typ urządzenia i wersję systemu z formatów wiadomości, a w AirDrop błędy w contact discovery pozwalają wyciągać identyfikatory kontaktów.",
        "defense": "PrivateDrop jest odpowiedzią na te błędy, bo przenosi mutual authentication do PSI i zachowuje czas odpowiedzi poniżej jednej sekundy. Testy muszą obejmować różne stany zasięgu, typ transportu, liczbę identyfikatorów i ścieżki zgłoszone przez reverse engineering, bo dopiero wtedy widać, czy format wiadomości nadal przecieka.",
        "subtopics": {
            "Continuity overview": "Apple's Continuity obejmuje Handoff, Universal Clipboard i Wi-Fi Password Sharing.",
            "Handoff discovery": "Handoff zaczyna się od BLE discovery i przenosi activity state w stacku Continuity.",
            "AirDrop discovery": "AirDrop używa discovery, authentication i transferu na bazie BLE, AWDL i Wi-Fi.",
            "PrivateDrop": "PrivateDrop zastępuje leaked contact checks mechanizmem PSI, żeby nie ujawniać phone number ani email.",
            "AWDL and BLE": "AWDL i BLE niosą niskopoziomowy ruch discovery oraz widoczny dla użytkownika stan Continuity.",
            "Cross-device identity": "Messagi Continuity mogą ujawniać typ urządzenia, wersję OS i zachowanie pasywnemu obserwatorowi.",
            "Spoof relay downgrade": "Atakujący może spoofować, relayować albo downgrade'ować discovery i authentication.",
            "Transport and state machine": "Structured analysis wymaga obserwacji całego state machine na różnych vantage points macOS.",
            "Packet analysis": "Packet captures pokazują, które pola są szyfrowane, a które metadata lecą jawnie.",
            "Mitigations": "PSI, większa ostrożność w contact discovery i twardsza kontrola widoczności ograniczają wyciek.",
            "Test matrix": "Dobry test matrix zmienia stan urządzenia, odległość i użyty transport.",
            "Android comparison": "Android local-network policy daje użyteczny kontrast dla zawsze aktywnych kanałów continuity.",
        },
    },
]


def aspect_block(aspect: str) -> tuple[str, str, str, str]:
    if aspect == "Co to jest":
        return (
            "Definicja i granica pojęcia",
            "Dlaczego to nie jest tylko hasło",
            "Jakie miejsce ma w modelu zagrożeń",
            "Dlaczego ten mechanizm istnieje",
        )
    if aspect == "Jak działa":
        return (
            "Wejście i stan początkowy",
            "Krok po kroku przez przepływ",
            "Decyzja systemu i stan pośredni",
            "Wynik oraz konsekwencja",
        )
    if aspect == "Jak pęka":
        return (
            "Warunek powodzenia ataku",
            "Co kontroluje atakujący",
            "Gdzie system ufa za dużo",
            "Skutek dla danych lub dostępu",
        )
    return (
        "Reguła i miejsce egzekwowania",
        "Minimalny zakres dostępu",
        "Wersja systemu i kompatybilność",
        "Test i regresja",
    )


def short_phrase(text: str, limit: int = 8) -> str:
    import re

    text = re.split(r"[.;]", text, maxsplit=1)[0]
    words = text.replace("(", "").replace(")", "").replace(",", "").split()
    if len(words) <= limit:
        return text
    return " ".join(words[:limit]).rstrip(".") + "…"


def bullets_for(block: dict, subtopic: str, aspect: str) -> list[str]:
    specific = block["subtopics"][subtopic]
    lead = block["lead"]
    mechanics = block["mechanics"]
    attack = block["attack"]
    defense = block["defense"]

    if aspect == "Co to jest":
        return [
            specific,
            short_phrase(lead, 8),
            short_phrase(mechanics, 8),
        ]
    if aspect == "Jak działa":
        return [
            f"{subtopic}: {short_phrase(mechanics, 8)}",
            f"{subtopic}: {short_phrase(lead, 8)}",
            f"{subtopic}: {short_phrase(defense, 8)}",
        ]
    if aspect == "Jak pęka":
        return [
            f"{subtopic}: {short_phrase(attack, 8)}",
            f"{subtopic}: {short_phrase(mechanics, 8)}",
            f"{subtopic}: {short_phrase(lead, 8)}",
        ]
    return [
        f"{subtopic}: {short_phrase(defense, 8)}",
        f"{subtopic}: {short_phrase(mechanics, 8)}",
        f"{subtopic}: {short_phrase(attack, 8)}",
    ]


def teleprompter(num: int, block: dict, subtopic: str, aspect: str) -> str:
    specific = block["subtopics"][subtopic]
    lead = block["lead"]
    mechanics = block["mechanics"]
    attack = block["attack"]
    defense = block["defense"]
    if aspect == "Co to jest":
        first = specific
    elif aspect == "Jak działa":
        first = f"{subtopic} zaczyna się od stanu początkowego i kończy na wyniku, który można zaobserwować w API, callbacku albo rekordzie protokołu."
    elif aspect == "Jak pęka":
        first = f"{subtopic} przestaje być bezpieczny, gdy przeciwnik przejmuje sygnał albo dane uznane przez system za zaufane."
    else:
        first = f"{subtopic} wymaga konkretnej reguły i miejsca egzekwowania."

    if aspect == "Co to jest":
        p2 = f"{lead} {mechanics}"
        p3 = f"{attack} {specific} pokazuje, gdzie systemowi wolno ufać, a gdzie powinien odrzucić lokalny sygnał."
        p4 = f"{defense} Weryfikacja musi obejmować przypadek błędny, przypadek poprawny i stan po revocation."
    elif aspect == "Jak działa":
        p2 = f"{block['mechanics']} Kolejność zdarzeń pokazuje, gdzie system przejmuje kontrolę, a gdzie pozostawia decyzję aplikacji."
        p3 = "Jeżeli źródło opisuje API, callback albo rekord protokołu, trzeba podać pola, kolejność i to, który element decyduje o następnym kroku. Port, flaga, nagłówek albo callback nie są ozdobą, tylko częścią decyzji bezpieczeństwa."
        p4 = "Na końcu sekwencji pojawia się konkretny stan: dostęp przyznany, dostęp odrzucony, URI zgrantowane, pakiet wysłany albo kod załadowany. To jest miejsce, w którym widać różnicę między poprawnym przepływem a obejściem."
    elif aspect == "Jak pęka":
        p2 = block["attack"]
        p3 = "Jeśli exploit path opiera się na podmianie, spoofingu, stale cache albo zbyt szerokim zakresie dostępu, trzeba to nazwać wprost. Bez wskazania wejścia i punktu przejęcia atak nie jest opisany, tylko zasugerowany."
        p4 = "Skutek ma być policzalny: wyciek danych, przejęcie zasobu, obejście ograniczenia albo awaria usługi. Trzeba też powiedzieć, czy atak daje odczyt, zapis, pełne wykonanie albo tylko degradację usługi."
    else:
        p2 = block["defense"]
        p3 = "Jeżeli obrona zależy od parsera, manifestu, systemowego pickera albo odświeżenia stanu, to właśnie to jest rdzeń tego slajdu. Trzeba jeszcze wskazać, czy reguła działa przed wejściem, po wejściu czy dopiero przy użyciu zasobu."
        p4 = "Test musi pokazać, że przypadek zły odpadł, a dobry przeszedł bez otwierania szerszego dostępu niż to konieczne. Bez testu nie wiadomo, czy reguła działa, czy tylko wygląda dobrze na slajdzie."

    return (
        f"{first}\n"
        f"{p2}\n"
        f"{p3}\n"
        f"{p4}"
    )


def render_slide(num: int, block: dict, subtopic: str, aspect: str) -> str:
    layout = "definition" if aspect == "Co to jest" else "bullet"
    lines = [
        f"#slide {num}",
        "## layout",
        layout,
        "## slide title",
        subtopic,
        "## subtitle",
        aspect,
    ]
    if aspect == "Co to jest":
        lines += [
            "## term",
            subtopic,
            "## definition",
            block["subtopics"][subtopic],
        ]
    else:
        lines += ["## bullets"]
        for bullet in bullets_for(block, subtopic, aspect):
            lines.append(f"- {bullet}")
    lines += [
        "## teleprompter:",
        teleprompter(num, block, subtopic, aspect),
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    slide_num = 1
    for block in BLOCKS:
        path = OUT_DIR / block["file"]
        chunks: list[str] = []
        for subtopic in block["subtopics"]:
            for aspect_name, _, _ in ASPECTS:
                chunks.append(render_slide(slide_num, block, subtopic, aspect_name))
                slide_num += 1
        path.write_text("\n".join(chunks), encoding="utf-8")


if __name__ == "__main__":
    main()
