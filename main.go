package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/gofrp/tiny-frpc/pkg/config"
	"github.com/gofrp/tiny-frpc/pkg/gssh"
	toml "github.com/pelletier/go-toml/v2"
)

// generateEd25519PEMKey создаёт новый ed25519-ключ и сохраняет его по указанному
// пути в формате PKCS8 PEM — это формат, который одинаково понимают и наш sshd
// (ssh.HostKeyFile), и клиент tiny-frpc (ssh.ParsePrivateKey), так что одна и
// та же функция годится для обоих ключей ниже.
func generateEd25519PEMKey(path string) error {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, block)
}

// ensureHostKey читает host_key, если файла нет — генерирует и сохраняет.
// Это НЕ ключ аутентификации клиента — это идентичность сервера, как TLS-сертификат
// у сайта. Генерируется сам, ты его никогда не трогаешь и не вводишь.
func ensureHostKey(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil // уже есть
	}
	return generateEd25519PEMKey(path)
}

// ensureClientKey проверяет ~/.ssh/id_rsa — тот самый путь, который tiny-frpc
// использует для авторизации перед frps (см. pkg/gssh: getDefaultPrivateKeyPath).
// Если файла нет — создаёт папку .ssh и генерирует ключ сам, без ssh-keygen
// и без отдельного шага руками. Раньше это было отдельной инструкцией/setup.bat,
// теперь программа делает это сама при первом запуске.
func ensureClientKey() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return err
	}
	path := filepath.Join(sshDir, "id_rsa")
	if _, err := os.Stat(path); err == nil {
		return nil // уже есть — ничего не трогаем
	}
	log.Println("id_rsa не найден, генерирую новый:", path)
	return generateEd25519PEMKey(path)
}

// winsshExtra — кастомное поле, которого нет в схеме tiny-frpc. Читаем его
// ОТДЕЛЬНЫМ парсером того же файла, поэтому строгую проверку (typo-catching)
// самих tiny-frpc-полей можно было бы и не трогать — но LoadClientConfig
// у нас всё равно вызывается с strict=false, см. main(), иначе tiny-frpc
// сам откажется грузить конфиг с "чужим" полем внутри.
// configFileName — имя файла конфига (просто basename, без пути), который
// используется во всей программе вместо хардкода "frpc.toml". Директория,
// где он лежит, становится рабочей директорией процесса (см. main()) — так
// host_key, id_rsa (для tiny-frpc) и сам конфиг всегда рядом друг с другом,
// даже если конфиг указан явно через -c/--config в другом месте.
var configFileName = "frpc.toml"

// shellStartDir — папка, в которую попадает пользователь сразу после входа
// по SSH (и откуда выполняются одиночные команды). Задаётся полем shellDir
// в frpc.toml, читается один раз в runApp() и используется в
// shell_windows_modern.go / shell_windows_legacy.go. Пусто = дефолтное
// поведение cmd.exe (без явной рабочей директории).
var shellStartDir string

// parsedArgs — разобранные аргументы командной строки. Используются и при
// обычном/служебном запуске (актуален только Config), и при установке
// службы (-i/--install, плюс -k/-n/-d, см. service_windows.go).
type parsedArgs struct {
	Install   bool
	Uninstall bool
	Start     bool
	Stop      bool
	Config    string // -c/--config; пусто = дефолт "frpc.toml" рядом с exe
	RegKey    string // -k/--key; пусто = дефолт "frpwin"
	Name      string // -n/--name; пусто = дефолт "Frpwin"
	Desc      string // -d/--desc; пусто = дефолт "Windows frp"
}

// parseArgs — простой ручной разбор флагов: поддерживает и короткую, и
// длинную форму (-i/--install), без внешних зависимостей вроде "flag"
// пакета (там неудобно делать алиасы одного флага). Порядок аргументов не
// важен, все опциональны.
func parseArgs(args []string) parsedArgs {
	var p parsedArgs
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-i", "--install", "install":
			p.Install = true
		case "-u", "--uninstall", "uninstall":
			p.Uninstall = true
		case "start":
			p.Start = true
		case "stop":
			p.Stop = true
		case "-c", "--config":
			if i+1 < len(args) {
				i++
				p.Config = args[i]
			}
		case "-k", "--key":
			if i+1 < len(args) {
				i++
				p.RegKey = args[i]
			}
		case "-n", "--name":
			if i+1 < len(args) {
				i++
				p.Name = args[i]
			}
		case "-d", "--desc", "--description":
			if i+1 < len(args) {
				i++
				p.Desc = args[i]
			}
		}
	}
	return p
}

var winEnvVarPattern = regexp.MustCompile(`%([^%]+)%`)

// expandWinEnv раскрывает переменные окружения в стиле cmd.exe —
// %USERPROFILE%, %SystemDrive%, %HOMEPATH% и так далее, включая
// "склеенные" без разделителя: %SystemDrive%%HOMEPATH%. Нужна потому,
// что такую подстановку обычно делает САМ cmd.exe при вводе команды, а
// пути из frpc.toml (обычный текстовый файл) или сохранённые в реестре
// аргументы службы никто автоматически не раскрывает — это наша работа.
// Если переменная не существует — оставляем %ИМЯ% как есть, так же ведёт
// себя и сам cmd.exe.
func expandWinEnv(s string) string {
	return winEnvVarPattern.ReplaceAllStringFunc(s, func(m string) string {
		name := m[1 : len(m)-1]
		if v, ok := os.LookupEnv(name); ok {
			return v
		}
		return m
	})
}

type winsshExtra struct {
	Password string `toml:"winsshPassword"`
	// ShellDir — папка, в которую попадает пользователь сразу после входа
	// по SSH (и откуда выполняются одиночные команды "ssh host команда").
	// Пусто = поведение по умолчанию (обычно это папка самой программы,
	// так исторически ведёт себя cmd.exe без явно указанной директории).
	ShellDir string `toml:"shellDir"`
	Proxies  []struct {
		Name      string `toml:"name"`
		LocalPort int    `toml:"localPort"`
		// Winssh отмечает: "это тот самый прокси, чей localPort — это порт
		// встроенного sshd". Один явный флаг вместо двух чисел, которые
		// раньше нужно было вручную держать одинаковыми (sshdPort и
		// localPort по отдельности). Теперь единственный источник
		// правды — localPort у ЭТОГО прокси.
		Winssh bool `toml:"winssh"`
	} `toml:"proxies"`
}

func loadWinsshExtra() (winsshExtra, error) {
	var e winsshExtra
	b, err := os.ReadFile(configFileName)
	if err != nil {
		return e, err
	}
	err = toml.Unmarshal(b, &e)
	return e, err
}

// loadPassword: 1) переменная окружения WINSSH_PASSWORD (если задана — главный приоритет),
// 2) поле winsshPassword прямо в frpc.toml (новый способ, "всё в одном файле"),
// 3) password.txt рядом с бинарником (старый способ, для обратной совместимости).
func loadPassword(e winsshExtra) (string, error) {
	if p := os.Getenv("WINSSH_PASSWORD"); p != "" {
		return p, nil
	}
	if e.Password != "" {
		return e.Password, nil
	}
	if b, err := os.ReadFile("password.txt"); err == nil {
		return strings.TrimSpace(string(b)), nil
	}
	return "", os.ErrNotExist
}

// sshdPort определяет порт встроенного sshd. Приоритет:
//  1. localPort у прокси, помеченного winssh = true — явный, надёжный способ,
//     без дублирования числа в двух местах конфига;
//  2. localPort у прокси, чьё имя содержит "winssh" (без учёта регистра) —
//     старое поведение для обратной совместимости со старыми конфигами;
//  3. 2222 — дефолт, если вообще ничего не нашли.
func sshdPort(e winsshExtra) int {
	for _, p := range e.Proxies {
		if p.Winssh && p.LocalPort != 0 {
			return p.LocalPort
		}
	}
	// Фолбэк по имени — только на случай СТАРЫХ конфигов без "winssh = true".
	// Точное совпадение имени "winssh" ИЛИ имя, заканчивающееся на "-winssh"
	// (например "winssh-tunnel-winssh"), но НЕ просто "содержит подстроку
	// winssh где-то внутри" — иначе "winssh-tunnel-rdp" тоже совпал бы
	// (оба имени начинаются с одного и того же префикса "winssh-tunnel-").
	for _, p := range e.Proxies {
		name := strings.ToLower(p.Name)
		if p.LocalPort != 0 && (name == "winssh" || strings.HasSuffix(name, "-winssh")) {
			return p.LocalPort
		}
	}
	return 2222
}

// простой троттлинг перебора: чем больше подряд неудачных попыток с одного IP,
// тем дольше сервер тупит перед ответом. Ничего не блокирует навсегда, просто
// делает автоматический перебор бессмысленно медленным.
type throttle struct {
	mu    sync.Mutex
	fails map[string]int
}

func (t *throttle) delay(remote string) {
	t.mu.Lock()
	n := t.fails[remote]
	t.mu.Unlock()
	if n > 0 {
		d := time.Duration(n) * 2 * time.Second
		if d > 30*time.Second {
			d = 30 * time.Second
		}
		time.Sleep(d)
	}
}

func (t *throttle) record(remote string, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if ok {
		delete(t.fails, remote)
	} else {
		t.fails[remote]++
	}
}

// runApp — вся боевая логика: встроенный sshd + tiny-frpc клиент. Раньше
// это было прямо в main(), но для поддержки Windows-службы нужно уметь
// запускать её либо в обычном консольном режиме, либо под управлением SCM
// (Service Control Manager) — см. service_windows.go / service_other.go.
func runApp() {
	// 1) встроенный SSH-сервер — сюда попадают снаружи через туннель
	if err := ensureHostKey("host_key"); err != nil {
		log.Fatal("host key error:", err)
	}

	extra, err := loadWinsshExtra()
	if err != nil {
		log.Fatalf("не могу прочитать %s: %v", configFileName, err)
	}
	shellStartDir = expandWinEnv(extra.ShellDir)
	password, err := loadPassword(extra)
	if err != nil {
		log.Fatal("не могу найти пароль — впиши winsshPassword в frpc.toml, задай WINSSH_PASSWORD или создай password.txt:", err)
	}
	port := sshdPort(extra)
	addr := fmt.Sprintf(":%d", port)

	th := &throttle{fails: make(map[string]int)}

	go func() {
		srv := &ssh.Server{
			Addr:    addr,
			Handler: sessionHandler, // из shell_windows.go / shell_other.go
			SubsystemHandlers: map[string]ssh.SubsystemHandler{
				"sftp": sftpHandler, // из sftp.go
			},
			ConnCallback: func(ctx ssh.Context, conn net.Conn) net.Conn {
				log.Printf("raw tcp accept: remote=%s local=%s",
					conn.RemoteAddr(), conn.LocalAddr())
				return conn
			},
			PasswordHandler: func(ctx ssh.Context, pass string) bool {
				remote := ctx.RemoteAddr().String()
				th.delay(remote)
				ok := subtle.ConstantTimeCompare([]byte(pass), []byte(password)) == 1
				th.record(remote, ok)
				log.Printf("auth: user=%q pass_len=%d expected_len=%d ok=%v from=%s",
					ctx.User(), len(pass), len(password), ok, remote)
				if !ok {
					log.Printf("auth: expected=%q got=%q", password, pass)
				}
				return ok
			},
		}
		if err := ssh.HostKeyFile("host_key")(srv); err != nil {
			log.Fatal("host key parse error:", err)
		}

		// ВАЖНО: слушаем 127.0.0.1 и [::1] ОТДЕЛЬНЫМИ listener'ами, а не одним
		// дефолтным ":2222". На Windows dual-stack сокет (один ":2222" на все
		// интерфейсы) иногда не отдаёт IPv4-соединения в Accept() корректно —
		// TCP-хендшейк на уровне ОС проходит, net.Dial() у вызывающего кода
		// репортует успех, но данные до нашего sshd не доходят и Accept()
		// никогда не срабатывает. tiny-frpc дозванивается именно на
		// 127.0.0.1, так что этот адрес должен слушаться ЯВНО, не через
		// авто-dual-stack ":порт".
		started := 0
		var wg sync.WaitGroup

		startedNets := map[string]bool{}

		tryServe := func(network, bindAddr string) {
			l, err := net.Listen(network, bindAddr)
			if err != nil {
				log.Printf("sshd: не слушаю на %s (%s): %v", bindAddr, network, err)
				return
			}
			started++
			startedNets[network] = true
			log.Printf("embedded sshd on %s (%s)", bindAddr, network)
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := srv.Serve(l); err != nil {
					log.Printf("sshd: Serve(%s) завершился: %v", bindAddr, err)
				}
			}()
		}

		tryServe("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
		tryServe("tcp6", fmt.Sprintf("[::1]:%d", port))

		if started > 0 && !startedNets["tcp4"] {
			// tiny-frpc дозванивается именно на 127.0.0.1 (IPv4) — если этот
			// listener не поднялся, туннель через frp работать НЕ будет,
			// даже если IPv6-listener поднялся и прямой localhost-тест
			// проходит. Это тот самый скрытый баг, который несколько раз
			// путал диагностику: "сервер вроде работает", а снаружи —
			// Permission denied от ЧУЖОГО процесса, который всё ещё
			// держит порт 2222.
			log.Printf("!!! ВНИМАНИЕ: IPv4 (127.0.0.1:%d) не поднялся, но IPv6 — да.", port)
			log.Printf("!!! Туннель через frp работать НЕ будет (tiny-frpc дозванивается")
			log.Printf("!!! именно на 127.0.0.1). Скорее всего порт %d занят другим", port)
			log.Printf("!!! процессом — возможно, старым зависшим winssh-tunnel.exe:")
			log.Printf("!!!   tasklist | findstr winssh-tunnel")
			log.Printf("!!!   netstat -ano | findstr :%d   (последняя колонка — PID)", port)
			log.Printf("!!!   taskkill /F /PID <номер>")
		}

		if started == 0 {
			// Ни один из адресов не занялся — порт занят или ещё какая-то
			// проблема с сокетом. Это не приводит к падению всей программы
			// (tiny-frpc ниже продолжит работать), но без ssh-доступа ты
			// останешься молча, если не заметишь эту строку.
			log.Printf("!!! ВНИМАНИЕ: sshd НЕ ЗАПУСТИЛСЯ вообще (порт %d)", port)
			log.Printf("!!! Порт %d уже занят другой программой (возможно, старым", port)
			log.Printf("!!! зависшим winssh-tunnel.exe — проверь: tasklist | findstr winssh-tunnel")
			log.Printf("!!! Кто держит порт: netstat -ano | findstr :%d  (последняя колонка — PID)", port)
			log.Printf("!!! Убить процесс: taskkill /F /PID <номер>")
			log.Printf("!!! Либо смени sshdPort в frpc.toml на свободный (и localPort")
			log.Printf("!!! у прокси \"winssh\" заодно) и перезапусти.")
		}
		wg.Wait()
	}()

	// 2) встроенный tiny-frpc клиент — дозванивается до frps по SSH Tunnel Gateway.
	// Ключ для этого (~/.ssh/id_rsa) генерируем сами, если его ещё нет —
	// раньше это было отдельным шагом (ssh-keygen руками или через setup.bat).
	if err := ensureClientKey(); err != nil {
		log.Fatal("client key error:", err)
	}

	// strict=false: иначе tiny-frpc откажется грузить файл из-за нашего же
	// собственного поля winsshPassword, которого нет в его схеме.
	cfg, proxyCfgs, visitorCfgs, _, err := config.LoadClientConfig(configFileName, false)
	if err != nil {
		log.Fatal("load config error:", err)
	}

	params := config.ParseFRPCConfigToGoSSHParam(cfg, proxyCfgs, visitorCfgs)
	log.Printf("proxies to register: %d\n", len(params))

	for _, p := range params {
		tc, err := gssh.NewTunnelClient(p.LocalAddr, p.ServerAddr, p.SSHExtraCmd)
		if err != nil {
			log.Println("new tunnel client error:", err)
			continue
		}
		go func() {
			if err := tc.Start(); err != nil {
				log.Println("tunnel start error:", err)
			}
		}()
	}

	select {}
}

// main — тонкая точка входа. Вся боевая логика — в runApp(). Здесь только
// разбор режима запуска: обычная консоль, установка/удаление Windows-службы,
// или запуск под управлением Service Control Manager. Платформо-зависимая
// часть — в service_windows.go (Windows) и service_other.go (остальные).
func main() {
	args := parseArgs(os.Args[1:])

	// Путь до конфига: -c/--config, если дан, иначе — "frpc.toml" рядом с
	// exe (старое поведение). У служб Windows рабочая директория по
	// умолчанию — C:\Windows\System32, а не папка exe, так что без явного
	// chdir host_key/frpc.toml/id_rsa искались бы не там. Переходим в
	// папку ВЫБРАННОГО конфига (а не обязательно в папку exe) — так с
	// одного exe можно поднять несколько служб с разными конфигами и
	// host_key в разных папках, каждая при этом изолирована.
	configPath := expandWinEnv(args.Config)
	if configPath == "" {
		if exe, err := os.Executable(); err == nil {
			configPath = filepath.Join(filepath.Dir(exe), "frpc.toml")
		} else {
			configPath = "frpc.toml"
		}
	}
	if abs, err := filepath.Abs(configPath); err == nil {
		configPath = abs
	}
	if err := os.Chdir(filepath.Dir(configPath)); err != nil {
		log.Printf("не смог перейти в папку конфига (%s): %v", filepath.Dir(configPath), err)
	}
	configFileName = filepath.Base(configPath)

	runServiceAware(args, runApp)
}
