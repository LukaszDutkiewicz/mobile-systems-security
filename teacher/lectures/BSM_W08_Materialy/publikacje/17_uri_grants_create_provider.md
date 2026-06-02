# URI grants and create content provider

- Zrodlo 1: https://developer.android.com/guide/topics/providers/content-provider-creating
- Zrodlo 2: https://developer.android.com/guide/topics/manifest/grant-uri-permission-element
- Temat: uprawnienia do `content URI`

## Teza
- Trzecie zrodlo jest potrzebne, bo pokazuje mechanike tworzenia providera i granularnych reguł grantowania URI.
- To dobry material do wytlumaczenia, jak kontrola dostepu przechodzi od ogolnego provider access do konkretnego zasobu.

## Co czytac
- W `Create a content provider`: manifest, `android:grantUriPermissions`, flagi temporary permissions
- W `<grant-uri-permission>`: reguly per path
- W obu: relacja miedzy providerem, intentem i odbiorca

## Frazy do znalezienia
- `grantUriPermissions`
- `grant-uri-permission`
- `FLAG_GRANT_READ_URI_PERMISSION`
- `FLAG_GRANT_WRITE_URI_PERMISSION`
- `path`

## Co jest na stronie
- Dokumentacja pokazuje, ze provider moze przyznawac dostep tylko do wybranych URI i tylko w określonym trybie.
- Fragment o `<grant-uri-permission>` podkreśla, ze dostep moze byc ograniczony sciezka.
- Przy tworzeniu providera istotne jest to, ze URI permission nie jest rownoznaczne z pelnym permission na cala baze.

## Co wyciagnac
- granularna polityka dostepu do danych
- dobry most do FileProvider i do tematu bezpiecznego eksportu danych
