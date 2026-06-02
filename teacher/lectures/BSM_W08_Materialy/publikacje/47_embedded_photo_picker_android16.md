# Embedded photo picker Android 16

- Zrodlo: https://developer.android.com/training/data-storage/shared/photo-picker/embedded
- Temat: embedded photo picker i selected media

## Teza
- Embedded photo picker pozwala osadzic wybor mediow wewnatrz UI aplikacji, ale zachowuje izolacje procesu i model prywatnosci standardowego pickera.

## Co czytac
- Overview
- How it works
- SurfaceView / setChildSurfacePackage
- Continuous selection
- Callbacki URIs

## Frazy do znalezienia
- `SurfaceView`
- `setChildSurfacePackage`
- `continuous select`
- `onUriPermissionGranted`
- `onUriPermissionRevoked`

## Co jest na stronie
- Picker moze byc renderowany wewnatrz hierarchii widoku aplikacji.
- Klient pozostaje resumed i moze reagowac na wybor w czasie rzeczywistym.
- Wsparcie obejmuje Android 14 API 34 z SDK Extensions 15+.

## Co wyciagnac
- jak osadzenie pickera nie znosi granicy bezpieczenstwa
- jak dzialaja deselect i revoke flow
- jak cloud media providers wchodza do jednego kontraktu

