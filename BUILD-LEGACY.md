# Сборка winssh-tunnel-legacy.exe (Windows 7 / Server 2008R2+)

Это не то же самое, что основной go.mod — legacy-версии нужны Go 1.20
(последняя версия Go, которая вообще собирает под такие старые
системы) и более старые версии части зависимостей, которые сами
подняли планку go-директивы выше, чем нужно.

## Зависимости (другой набор версий, не как в основном go.mod)

```
go 1.20

require (
    github.com/gliderlabs/ssh v0.3.8
    github.com/gofrp/tiny-frpc v0.1.3
    github.com/pelletier/go-toml/v2 v2.0.8      // не v2.4.3 — та требует go 1.21
    github.com/iamacarpet/go-winpty v1.0.4       // вместо UserExistsError/conpty
    github.com/pkg/sftp v1.13.7
    golang.org/x/crypto v0.17.0                  // не v0.37.0 — та требует go 1.23
    golang.org/x/sys v0.15.0
)
```

## Команда сборки

```
go build -tags legacy -o winssh-tunnel-legacy.exe .
```

Флаг `-tags legacy` переключает main.go на shell_windows_legacy.go
(winpty) вместо shell_windows_modern.go (ConPTY) — они взаимоисключающие
через `//go:build windows && legacy` / `//go:build windows && !legacy`.

## Обязательно рядом с exe при запуске

`winpty.dll` и `winpty-agent.exe` (64-бит) — без них интерактивный
шелл откажется стартовать (само подключение и SFTP при этом всё равно
будут работать, упадёт только запрос шелла). Официальный релиз:

```
https://github.com/rprichard/winpty/releases/download/0.4.3/winpty-0.4.3-msvc2015.zip
→ x64/bin/winpty.dll
→ x64/bin/winpty-agent.exe
```

SHA256 (для сверки, что файлы не подменены):
```
winpty.dll:        936f611c2129600d35ab7aad45546a837f4f3a9ca7f673e5d66b48c313b9cd75
winpty-agent.exe:  9add1a61155ec47cf6f347faf776b746eebbde1dc9360d81b8a909da34650642
```
