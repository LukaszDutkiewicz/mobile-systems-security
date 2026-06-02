# Root detection and Android tips

- Zrodlo: https://developer.android.com/privacy-and-security/security-tips
- Temat: wykrywanie roota / stan urzadzenia

## Teza
- Android security tips nie daje prostego root detectora, ale dobrze pokazuje, jak myślec o zaufaniu do urzadzenia i o sygnalach, ktore warto sprawdzac przed operacjami wrażliwymi.
- To zrodlo pomaga zbudowac polityke, a nie tylko heurystyke.

## Co czytac
- Część o sandboxie i sandboxed apps
- Część o Play Integrity
- Część o credential exposure i ograniczaniu scope permissions

## Frazy do znalezienia
- `sandbox`
- `Play Integrity`
- `credentials`
- `permissions`
- `device integrity`

## Co jest na stronie
- Dokument przypomina, ze aplikacje dzialaja w sandboxie, ale nie zakladajmy, ze jest on nienaruszalny.
- Play Integrity jest wskazane jako mechanizm oceny zaufania do urzadzenia i aplikacji.
- To dobre zrodlo do pokazania, ze root detection jest tylko jednym z sygnalow w wiekszej polityce.

## Co wyciagnac
- root / device integrity jako element policy, nie samodzielny test
- do przygotowania slajdu o "defence in depth" dla urzadzenia
