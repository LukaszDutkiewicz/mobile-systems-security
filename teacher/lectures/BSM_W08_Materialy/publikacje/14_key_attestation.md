# Key attestation

- Zrodlo: https://developer.android.com/privacy-and-security/security-key-attestation
- Temat: atestacja klucza i hardware-backed trust

## Teza
- Key attestation pozwala zweryfikowac, ze klucz zostal utworzony w zaufanym, sprzetowo wspieranym srodowisku. To jest mocniejszy sygnal niz zwykly local check.
- W praktyce to mechanizm dla aplikacji, ktore nie chca opierac sie tylko na deklaracjach systemu.

## Co czytac
- Overview / concept: czym jest key attestation
- Attestation chain: jak buduje sie lancuch zaufania
- Hardware-backed keys: co oznacza dla bezpieczenstwa
- Limits / use cases: kiedy ma sens i czego nie obiecuje

## Co jest na stronie
- Dokumentacja pokazuje, ze klucz i jego pochodzenie moga byc przedstawione jako dowod dla backendu.
- Lancuch atestacji jest istotny, bo pozwala odroznic zwykly klucz od klucza ze sprzetowym zapleczem.
- To narzedzie nie zastepuje calej polityki bezpieczenstwa, ale wzmacnia jej wiarygodnosc.

## Co wyciagnac
- twarde zakotwiczenie zaufania po stronie sprzetu
- sensowny kontrast do prostego root check
- dobry budulec dla tematu "device integrity signals"
