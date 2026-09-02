package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
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
type winsshExtra struct {
	Password string `toml:"winsshPassword"`
	Proxies  []struct {
		Name      string `toml:"name"`
		LocalPort int    `toml:"localPort"`
	} `toml:"proxies"`
}

func loadWinsshExtra() (winsshExtra, error) {
	var e winsshExtra
	b, err := os.ReadFile("frpc.toml")
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

// sshdPort берёт localPort из прокси с именем "winssh" в frpc.toml — это тот же
// самый порт, который frp пробрасывает снаружи, так что sshd слушает ровно там,
// куда его отправляет конфиг. Одно число, одно место правки, без пересборки.
// Если прокси "winssh" не нашли — используем 2222 для обратной совместимости.
func sshdPort(e winsshExtra) int {
	for _, p := range e.Proxies {
		if p.Name == "winssh" && p.LocalPort != 0 {
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

func main() {
	// 1) встроенный SSH-сервер — сюда попадают снаружи через туннель
	if err := ensureHostKey("host_key"); err != nil {
		log.Fatal("host key error:", err)
	}

	extra, err := loadWinsshExtra()
	if err != nil {
		log.Fatal("не могу прочитать frpc.toml:", err)
	}
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
			PasswordHandler: func(ctx ssh.Context, pass string) bool {
				remote := ctx.RemoteAddr().String()
				th.delay(remote)
				ok := subtle.ConstantTimeCompare([]byte(pass), []byte(password)) == 1
				th.record(remote, ok)
				return ok
			},
		}
		if err := ssh.HostKeyFile("host_key")(srv); err != nil {
			log.Fatal("host key parse error:", err)
		}

		log.Println("embedded sshd on", addr)
		err := srv.ListenAndServe()
		if err != nil {
			// Порт занят или ещё какая-то проблема с сокетом — это не приводит
			// к падению всей программы (tiny-frpc ниже продолжит работать), но
			// без ssh-доступа ты останешься молча, если не заметишь эту строку.
			log.Printf("!!! ВНИМАНИЕ: sshd НЕ ЗАПУСТИЛСЯ на %s: %v", addr, err)
			log.Printf("!!! Скорее всего порт %d уже занят другой программой.", port)
			log.Printf("!!! Поменяй localPort у прокси \"winssh\" в frpc.toml на свободный")
			log.Printf("!!! (и remotePort заодно, если хочешь) и перезапусти.")
		}
	}()

	// 2) встроенный tiny-frpc клиент — дозванивается до frps по SSH Tunnel Gateway.
	// Ключ для этого (~/.ssh/id_rsa) генерируем сами, если его ещё нет —
	// раньше это было отдельным шагом (ssh-keygen руками или через setup.bat).
	if err := ensureClientKey(); err != nil {
		log.Fatal("client key error:", err)
	}

	// strict=false: иначе tiny-frpc откажется грузить файл из-за нашего же
	// собственного поля winsshPassword, которого нет в его схеме.
	cfg, proxyCfgs, visitorCfgs, _, err := config.LoadClientConfig("frpc.toml", false)
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
