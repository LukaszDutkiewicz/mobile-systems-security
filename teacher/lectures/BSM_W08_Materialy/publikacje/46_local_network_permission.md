# Local network permission

- Zrodlo: https://developer.android.com/privacy-and-security/local-network-permission
- Temat: lokalna siec i discovery

## Teza
- Dokument wyjasnia, ze sam `INTERNET` pozwala aplikacji dotykac lokalnej sieci, a nowy runtime permission ma to uporzadkowac.
- To dobre zrodlo do pokazania mDNS, SSDP, WebView inheritance i rozdzielenia opt-in od enforcement.

## Co czytac
- Overview
- Impact
- Android 16 guidance
- Android 17 enforcement
- Errors i NDK note

## Frazy do znalezienia
- `RESTRICT_LOCAL_NETWORK`
- `ACCESS_LOCAL_NETWORK`
- `mDNS`
- `SSDP`
- `WebView`
- `android_getnetworkblockedreason`

## Co jest na stronie
- W Android 16 funkcja jest opt-in, zeby developerzy mogli znalezc zaleznosci od implicit local network access.
- Android 17 wymusza nowy model i blokuje LAN domyslnie dla nowych targetow.
- W dokumencie sa tez konkretne scenariusze bledow socketow i opis tego, jak lokalny ruch jest blokowany.

## Co wyciagnac
- konkretne warunki opt-in i enforcement
- roznica miedzy broad access a pickerem
- zachowanie WebView i NDK przy braku uprawnienia

