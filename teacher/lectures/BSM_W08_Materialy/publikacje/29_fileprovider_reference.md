# FileProvider reference

- Zrodlo: https://developer.android.com/reference/androidx/core/content/FileProvider
- Temat: FileProvider

## Teza
- Reference daje najwazniejszy techniczny szczegol: `FileProvider` generuje `content://` URI zamiast `file://`, a granty sa tymczasowe i kontrolowane.

## Co czytac
- Class overview
- `getUriForFile`
- opisy `FLAG_GRANT_READ_URI_PERMISSION` i `FLAG_GRANT_WRITE_URI_PERMISSION`

## Frazy do znalezienia
- `content:// Uri`
- `file:/// Uri`
- `grantUriPermission`
- `FLAG_GRANT_READ_URI_PERMISSION`
- `FLAG_GRANT_WRITE_URI_PERMISSION`

## Co wyciagnac
- mechanizm kontrolowanego udostepniania pliku
