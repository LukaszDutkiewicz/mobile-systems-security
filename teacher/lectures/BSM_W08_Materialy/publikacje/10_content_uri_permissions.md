# Content URI permissions

- Zrodlo: https://developer.android.com/guide/topics/providers/content-provider-basics
- Temat: uprawnienia do `content URI`

## Teza
- Uprawnienie do `content URI` jest bardziej precyzyjne niz zwykle permission: dotyczy konkretnego zasobu, a nie calej aplikacji czy calego providera.
- To mechanizm, ktory trzeba dobrze rozumiec, bo latwo go uznac za "po prostu dostep do pliku", a faktycznie jest to kontrolowane przekazanie zasobu.

## Co czytac
- URI permissions: jak działa dostep do konkretnego URI
- grantUriPermissions / grant-uri-permission: jak provider zezwala na dzielony dostep
- Intent flags: jak odbiorca dostaje read/write access
- Example sections o Contacts Provider: pokazanie, ze URI permission moze dzialac nawet bez tradycyjnego permission

## Co jest na stronie
- Dokumentacja podkresla, ze kontrola dotyczy URI, a nie calego content providera.
- Wazne sa flagi w `Intent`, bo to one niosa tymczasowy dostep do danych.
- Wspomnienie o Contacts Provider pokazuje, ze ten mechanizm bywa alternatywa dla klasycznych uprawnien.

## Co wyciagnac
- dostep granularny, a nie globalny
- rola flag `Intent` w przekazaniu uprawnienia
- dobry kontrast do tematow o leak surface i nadmiernej ekspozycji
