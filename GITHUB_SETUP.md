# Как загрузить проект в GitHub репо

Ты скачал эту структуру проекта. Теперь нужно загрузить её в свой репо на GitHub.

## Способ 1: Через Git (рекомендуется)

### 1. Установи Git (если ещё нет)
https://git-scm.com/download/win

### 2. Клонируй пустой репо локально

```bash
git clone https://github.com/spicicpein/ssh-frps.git
cd ssh-frps
```

### 3. Скопируй все файлы проекта в эту папку

Скопируй все файлы из архива, который я подготовил, в папку `ssh-frps`:

```
ssh-frps/
├── .github/
│   └── workflows/
│       └── build.yml
├── .gitignore
├── main.go
├── shell_windows_modern.go
├── shell_windows_legacy.go
├── shell_other.go
├── sftp.go
├── go.mod
├── go.sum (если есть)
├── README.md
├── BUILD-LEGACY.md
├── QUICKSTART.md
├── frpc.toml.example
└── setup.bat
```

### 4. Добавь файлы в Git и сделай коммит

```bash
git add .
git commit -m "Initial commit: winssh-tunnel project structure and CI/CD"
```

### 5. Загрузи в GitHub

```bash
git push origin main
```

### 6. Создай первый релиз

Когда всё загрузится, создай тег для релиза:

```bash
git tag -a v0.1.0 -m "First release: winssh-tunnel with ConPTY support"
git push origin v0.1.0
```

GitHub Actions сам соберёт exe и создаст Release!

---

## Способ 2: Через веб-интерфейс GitHub (если Git не установлен)

### 1. Открой репо на GitHub
https://github.com/spicicpein/ssh-frps

### 2. Нажми "Add file" → "Upload files"

### 3. Перетащи все файлы из архива

### 4. Напиши коммит-сообщение: "Initial commit"

### 5. Нажми "Commit changes"

---

## После загрузки: как триггерить сборку релизов

### Способ A: Через Git

```bash
git tag -a v0.2.0 -m "Release v0.2.0"
git push origin v0.2.0
```

GitHub Actions автоматически соберёт exe и создаст Release.

### Способ B: Через веб-интерфейс GitHub

1. Открой "Releases" на GitHub
2. Нажми "Create a new release"
3. Выбери или создай тег: `v0.2.0`
4. Введи название и описание
5. Нажми "Publish release"

GitHub Actions сам соберёт exe и загрузит файлы в релиз!

---

## Структура релизов на GitHub

После первого релиза твой репо будет выглядеть так:

```
Releases
├── v0.1.0 (Latest)
│   ├── winssh-tunnel.exe (10 MB)
│   ├── winssh-tunnel-legacy.exe (8.5 MB)
│   ├── winpty.dll (625 KB)
│   ├── winpty-agent.exe (711 KB)
│   ├── setup.bat
│   └── README.md
```

Пользователи просто скачивают нужный exe и всё!

---

## Проверка GitHub Actions

Когда создаст релиз, GitHub Actions автоматически:
1. Скачает Go 1.24
2. Собирает winssh-tunnel.exe
3. Собирает winssh-tunnel-legacy.exe (с Go 1.20)
4. Скачает winpty.dll и winpty-agent.exe с проверкой SHA256
5. Создаст Release и загрузит все файлы

Процесс занимает ~5 минут.

Проверить статус можно на вкладке "Actions" в репо.

---

## Дальнейшие обновления

Когда захочешь обновить код:

```bash
git add .
git commit -m "Fix: description of changes"
git push origin main
```

И когда готов к новому релизу:

```bash
git tag -a v0.2.0 -m "Release v0.2.0: description"
git push origin v0.2.0
```

Всё остальное делает GitHub Actions!

---

## Что находится в папке?

```
ssh-frps/
├── .github/workflows/build.yml  ← GitHub Actions workflow (основное)
├── .gitignore                   ← Исключает ключи, пароли, exe из репо
├── main.go                      ← Основной код (SSH + tiny-frpc)
├── shell_windows_modern.go      ← ConPTY (Windows 10+)
├── shell_windows_legacy.go      ← winpty (Windows 7+)
├── shell_other.go               ← Linux/Mac заглушка
├── sftp.go                      ← SFTP подсистема
├── go.mod                       ← Go модуль
├── README.md                    ← Полная документация
├── QUICKSTART.md                ← Быстрый старт (на русском)
├── BUILD-LEGACY.md              ← Инструкция по сборке legacy версии
├── frpc.toml.example            ← Пример конфига
└── setup.bat                    ← Батник для setup (Windows)
```

Основной файл для CI/CD: `.github/workflows/build.yml`

Он всё делает автоматически!
