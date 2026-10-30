# Сборка winssh-tunnel-legacy.exe (Windows 7 / 8 / 8.1 / Server 2008R2–2012R2)

Legacy отличается от обычной версии двумя вещами: интерактивный шелл идёт
через `winpty` (а не ConPTY, которого на этих системах нет), и собирается он
патченым тулчейном [XTLS/go-win7](https://github.com/XTLS/go-win7).
Стандартный Go для этих систем не подходит: последним официально
поддерживающим их был Go 1.20, а наш код и зависимости (Shadowsocks и др.)
требуют Go 1.23+.

## Сборка

```bash
# 1. тулчейн (готовый архив из релизов go-win7, для linux-хоста)
curl -L -o go-win7.zip https://github.com/XTLS/go-win7/releases/latest/download/go-for-win7-linux-amd64.zip
unzip go-win7.zip -d go-win7-sdk

# 2. сборка (тег legacy выбирает shell_windows_legacy.go вместо shell_windows_modern.go)
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 GOFLAGS="-mod=vendor -tags=legacy" \
  ./go-win7-sdk/bin/go build -o winssh-tunnel-legacy.exe .
```

## Что должно лежать рядом с exe при запуске

`winpty.dll` и `winpty-agent.exe` (64-бит) — без них интерактивный шелл
откажется стартовать с понятной ошибкой (SFTP и подключение при этом
работают). Они уже есть в репозитории. Источник и контрольные суммы:

```
https://github.com/rprichard/winpty/releases/download/0.4.3/winpty-0.4.3-msvc2015.zip
→ x64/bin/winpty.dll
→ x64/bin/winpty-agent.exe

SHA256:
winpty.dll:        936f611c2129600d35ab7aad45546a837f4f3a9ca7f673e5d66b48c313b9cd75
winpty-agent.exe:  9add1a61155ec47cf6f347faf776b746eebbde1dc9360d81b8a909da34650642
```

## Патчи в vendor/github.com/iamacarpet/go-winpty

Библиотека go-winpty в `vendor/` **изменена** (места помечены `PATCH(winssh-tunnel)`
в `winpty.go`). Если пересоздавать `vendor/` с нуля, патчи нужно перенести:

1. Ошибка запуска процесса: оригинал передавал в `winpty_spawn` нулевые
   указатели, из-за чего причина терялась («Error spawning process...»), и
   оставлял висеть `winpty-agent.exe`. Теперь возвращаются текст ошибки winpty
   и код `CreateProcess`, агент освобождается.
2. `AgentProcessHandle()` — хендл процесса агента (в оригинале объявлен, но не
   выведен наружу); нужен, чтобы поместить агента в Job Object и гарантированно
   убивать его вместе с шеллом.

## Проверено

Сборка и запуск на Windows Server 2012: вход, шелл, SFTP, завершение процессов
при закрытии окна. Windows 7, 8.1 и Server 2008R2 не проверялись, Vista
go-win7 не заявляет.
