# Быстрый старт winssh-tunnel

## За 5 минут до первого подключения

### 1. Скачай последний релиз

Иди на вкладку **Releases** в GitHub этого репо, скачай архив с последней версией:
- **winssh-tunnel.exe** — для Windows 10 (1809+) / Server 2019+
- **winssh-tunnel-legacy.exe** — для Windows 7 / Server 2008R2 и старше

### 2. Распакуй в отдельную папку

Например: `C:\ssh-frps\`

Внутри должны лежать:
```
C:\ssh-frps\
├── winssh-tunnel.exe
├── winssh-tunnel-legacy.exe  (если нужна поддержка Win7)
├── winpty.dll               (для legacy версии)
├── winpty-agent.exe         (для legacy версии)
├── frpc.toml.example
└── setup.bat
```

### 3. Скопируй и отредактируй конфиг

```bash
copy frpc.toml.example frpc.toml
```

Открой `frpc.toml` в блокноте и заполни:

```toml
serverAddr = "твой.vps.com"              # адрес твоего VPS
serverPort = 7000                         # обычно 7000
auth.token = "токен_из_frps"             # токен из frps.toml

winsshPassword = "любой_пароль"          # это пароль для SSH
```

Остальное менять не нужно.

### 4. Запусти программу

**Дважды кликни `winssh-tunnel.exe`** (или `winssh-tunnel-legacy.exe` для старых Windows).

При первом запуске программа:
- Создаст SSH-ключ в `~/.ssh/id_rsa` (если его нет)
- Создаст файл `host_key` рядом с exe (это сертификат сервера)
- Подключится к твоему frps
- Начнёт слушать на localhost:2222 (встроенный SSH-сервер)

### 5. Протестируй подключение

С **другой машины** (или даже с того же VPS, если у тебя есть SSH доступ):

```bash
ssh -p 6000 user@твой.vps.com
```

Пароль — то, что ты указал в `winsshPassword` в frpc.toml.

---

## Что видеть в окне программы

Нормальный лог:
```
embedded sshd on :2222
proxies to register: 1
```

Это значит всё работает. Если что-то пошло не так — там будет красная ошибка.

---

## Если что-то не работает

- **"Port already in use"** → Поменяй `localPort` для прокси "winssh" в frpc.toml
- **"host_key not found"** → Запусти программу ещё раз, она создаст ключ
- **"Connection refused"** → Проверь, включён ли SSH Tunnel Gateway на frps (`sshTunnelGateway.bindPort = 2200`)
- **"Authentication failed"** → Проверь пароль в frpc.toml
- **"Permission denied"** → Проверь, что winpty.dll и winpty-agent.exe лежат рядом с exe (для legacy версии)

---

## Нужен PowerShell вместо cmd.exe?

Отредактируй `shell_windows_modern.go` или `shell_windows_legacy.go`, строка:
```go
cpty.Start("cmd.exe", ...)  →  cpty.Start("powershell.exe", ...)
```

Пересобери:
```bash
go build -o winssh-tunnel.exe .
```

---

## Нужны другие туннели (RDP, SMB)?

В `frpc.toml` раскомментируй или добавь ещё `[[proxies]]` секции. Примеры уже там закомментированы.

Не требует пересборки exe — просто перезапусти программу.

---

Больше деталей в **README.md**. Удачи!
