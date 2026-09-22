package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/gofrp/tiny-frpc/pkg/config"
	"github.com/gofrp/tiny-frpc/pkg/util"
)

// ═══════════════════════════════════════════════════════════════════════
//  Часть 1: выбор способа подключения к frps (direct / proxy / auto)
// ═══════════════════════════════════════════════════════════════════════

// namedDialer — один способ установить TCP-соединение до сервера
// (напрямую или через конкретный прокси), с человекочитаемым именем для
// логов.
type namedDialer struct {
	name string
	dial func(target string) (net.Conn, error)
}

func directDialer() namedDialer {
	return namedDialer{
		name: "напрямую",
		dial: func(target string) (net.Conn, error) {
			return net.DialTimeout("tcp", target, 10*time.Second)
		},
	}
}

func proxyDialer(p connectProxyCfg) namedDialer {
	user, pass := "", ""
	if p.Auth {
		user, pass = p.User, p.Pass
	}
	typeLower := strings.ToLower(strings.TrimSpace(p.Type))
	name := fmt.Sprintf("%s-прокси %s", strings.ToUpper(typeLower), p.Addr)

	switch typeLower {
	case "socks5":
		return namedDialer{name: name, dial: func(target string) (net.Conn, error) {
			return dialViaSOCKS5(p.Addr, target, user, pass)
		}}
	case "http":
		return namedDialer{name: name, dial: func(target string) (net.Conn, error) {
			return dialViaHTTPProxy(p.Addr, target, user, pass)
		}}
	default:
		return namedDialer{name: name, dial: func(target string) (net.Conn, error) {
			return nil, fmt.Errorf("неизвестный тип прокси %q в connectProxy (поддерживаются: socks5, http)", p.Type)
		}}
	}
}

// buildDialerChain строит упорядоченный список способов подключения к
// frps по режиму connectMode из frpc.toml:
//   - "direct" (пусто/по умолчанию) — только напрямую, как было всегда
//   - "proxy"  — только через connectProxy, по очереди в том порядке,
//     в каком они перечислены в конфиге
//   - "auto"   — сначала напрямую, при неудаче — через connectProxy по
//     очереди
//
// runTunnel (ниже) идёт по этому списку по порядку при каждой попытке
// подключения/переподключения.
func buildDialerChain(extra winsshExtra) []namedDialer {
	mode := strings.ToLower(strings.TrimSpace(extra.ConnectMode))
	if mode == "" {
		mode = "direct"
	}

	var chain []namedDialer
	switch mode {
	case "direct":
		chain = append(chain, directDialer())
	case "proxy":
		for _, p := range extra.ConnectProxy {
			chain = append(chain, proxyDialer(p))
		}
	case "auto":
		chain = append(chain, directDialer())
		for _, p := range extra.ConnectProxy {
			chain = append(chain, proxyDialer(p))
		}
	default:
		log.Printf("connectMode: неизвестное значение %q (ожидается direct/proxy/auto), использую direct", extra.ConnectMode)
		chain = append(chain, directDialer())
	}

	if len(chain) == 0 {
		// mode == "proxy", но connectProxy пуст — без этого мы бы просто
		// зависли, пытаясь подключиться "никак". Явно откатываемся на
		// direct и громко об этом сообщаем, а не молчим.
		log.Printf("connectMode=%q, но список connectProxy пуст — использую direct", mode)
		chain = append(chain, directDialer())
	}

	names := make([]string, len(chain))
	for i, d := range chain {
		names[i] = d.name
	}
	log.Printf("подключение к frps: режим %q, порядок попыток: %s", mode, strings.Join(names, " → "))

	return chain
}

// ═══════════════════════════════════════════════════════════════════════
//  Часть 2: свой TunnelClient (аналог gssh.TunnelClient из tiny-frpc, но
//  с подключаемым способом установки TCP-соединения и с переподключением
//  при обрыве). Не патчим vendor напрямую — vendor у нас не коммитится в
//  git и пересобирается с нуля при каждой переустановке окружения, любой
//  прямой патч там был бы потерян при следующей пересборке.
// ═══════════════════════════════════════════════════════════════════════

type sshTunnelClient struct {
	localAddr string
	sshServer string
	command   string
	dial      func(target string) (net.Conn, error)

	authMethod ssh.AuthMethod
	sshConn    *ssh.Client
	ln         net.Listener
}

func defaultPrivateKeyPath() (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", err
	}
	return filepath.Join(usr.HomeDir, ".ssh", "id_rsa"), nil
}

func publicKeyAuth(path string) (ssh.AuthMethod, error) {
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("не могу прочитать приватный ключ: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("не могу разобрать приватный ключ: %w", err)
	}
	return ssh.PublicKeys(signer), nil
}

func newSSHTunnelClient(localAddr, sshServer, command string, dial func(target string) (net.Conn, error)) (*sshTunnelClient, error) {
	keyPath, err := defaultPrivateKeyPath()
	if err != nil {
		return nil, fmt.Errorf("не могу определить путь к приватному ключу: %w", err)
	}
	authMethod, err := publicKeyAuth(keyPath)
	if err != nil {
		return nil, err
	}
	return &sshTunnelClient{
		localAddr:  localAddr,
		sshServer:  sshServer,
		command:    command,
		dial:       dial,
		authMethod: authMethod,
	}, nil
}

// Start устанавливает SSH-соединение до frps (через c.dial — напрямую или
// через прокси) и держит его, пока оно живо. Возвращает ошибку/причину
// обрыва — в отличие от оригинальной gssh.TunnelClient.Start(), которая
// на обрыве слушателя молча возвращала nil, из-за чего снаружи было
// невозможно понять, что туннель умер, и переподключение было нечем
// триггерить.
func (c *sshTunnelClient) Start() error {
	conn, err := c.dial(c.sshServer)
	if err != nil {
		return err
	}

	clientConfig := &ssh.ClientConfig{
		User:            "v0",
		Auth:            []ssh.AuthMethod{c.authMethod},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	rawConn, chans, reqs, err := ssh.NewClientConn(conn, c.sshServer, clientConfig)
	if err != nil {
		conn.Close()
		return fmt.Errorf("SSH-хендшейк с %s не удался: %w", c.sshServer, err)
	}
	c.sshConn = ssh.NewClient(rawConn, chans, reqs)

	l, err := c.sshConn.Listen("tcp", "0.0.0.0:80")
	if err != nil {
		c.sshConn.Close()
		return err
	}
	c.ln = l

	session, err := c.sshConn.NewSession()
	if err != nil {
		c.sshConn.Close()
		return err
	}
	defer session.Close()

	if err := session.Start(c.command); err != nil {
		c.sshConn.Close()
		return err
	}

	log.Printf("session start cmd [%v] success", c.command)

	return c.serveListener()
}

func (c *sshTunnelClient) Close() {
	if c.sshConn != nil {
		_ = c.sshConn.Close()
	}
	if c.ln != nil {
		_ = c.ln.Close()
	}
}

func (c *sshTunnelClient) serveListener() error {
	for {
		conn, err := c.ln.Accept()
		if err != nil {
			return err
		}
		go c.handleConn(conn)
	}
}

func (c *sshTunnelClient) handleConn(conn net.Conn) {
	defer conn.Close()
	local, err := net.Dial("tcp", c.localAddr)
	if err != nil {
		log.Printf("ssh tunnel client dial %v error: %v", c.localAddr, err)
		return
	}
	_, _ = util.Join(local, conn)
}

// runTunnel держит один туннель (один прокси из frpc.toml) живым столько,
// сколько работает программа: пробует способы подключения из chain по
// очереди, при обрыве уже установленного соединения (не мгновенном сбое,
// см. connectedThreshold) начинает заново с начала списка — например,
// чтобы в auto-режиме при восстановлении прямой связи снова
// предпочесть её прокси.
func runTunnel(p config.GoSSHParam, chain []namedDialer) {
	const retryDelay = 10 * time.Second
	const connectedThreshold = 3 * time.Second

	for {
		reconnectNow := false
		for _, d := range chain {
			tc, err := newSSHTunnelClient(p.LocalAddr, p.ServerAddr, p.SSHExtraCmd, d.dial)
			if err != nil {
				log.Printf("туннель %s: %s: не смог подготовиться: %v", p.LocalAddr, d.name, err)
				continue
			}

			log.Printf("туннель %s: пробую через %s...", p.LocalAddr, d.name)
			started := time.Now()
			startErr := tc.Start()
			tc.Close()

			if time.Since(started) >= connectedThreshold {
				log.Printf("туннель %s: соединение через %s оборвалось (%v), переподключаюсь...", p.LocalAddr, d.name, startErr)
				reconnectNow = true
				break // начинаем заново с начала списка, не долистывая chain
			}
			log.Printf("туннель %s: %s не сработал (%v), пробую следующий способ", p.LocalAddr, d.name, startErr)
			// не break — пробуем следующий способ подключения в этом же круге
		}
		if !reconnectNow {
			log.Printf("туннель %s: не смог подключиться ни одним способом, жду %s и пробую снова", p.LocalAddr, retryDelay)
		}
		time.Sleep(retryDelay)
	}
}

// ═══════════════════════════════════════════════════════════════════════
//  Часть 3: минимальные клиенты SOCKS5 CONNECT и HTTP CONNECT — только
//  то, что нужно для проброса одного TCP-соединения (наш SSH до frps)
//  через прокси. Полноценный SOCKS5 (BIND, UDP ASSOCIATE) и полноценный
//  HTTP-клиент не нужны, поэтому пишем сами, без внешних зависимостей —
//  так vendor остаётся без единой лишней сторонней библиотеки.
// ═══════════════════════════════════════════════════════════════════════

// dialViaSOCKS5 устанавливает TCP-соединение до target через SOCKS5-прокси
// proxyAddr (RFC 1928, метод CONNECT). user/pass пустые — без авторизации.
func dialViaSOCKS5(proxyAddr, target, user, pass string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("не могу подключиться к SOCKS5-прокси %s: %w", proxyAddr, err)
	}
	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("некорректный адрес назначения %q: %w", target, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("некорректный порт назначения %q", portStr)
	}

	// --- Greeting: список методов аутентификации, которые мы предлагаем ---
	methods := []byte{0x00} // 0x00 = без авторизации
	if user != "" {
		methods = []byte{0x00, 0x02} // + 0x02 = логин/пароль (RFC 1929)
	}
	if _, err := conn.Write(append([]byte{0x05, byte(len(methods))}, methods...)); err != nil {
		return nil, fmt.Errorf("SOCKS5: ошибка отправки greeting: %w", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, fmt.Errorf("SOCKS5: ошибка чтения ответа на greeting: %w", err)
	}
	if resp[0] != 0x05 {
		return nil, fmt.Errorf("SOCKS5: сервер прислал неверную версию протокола (%d)", resp[0])
	}

	switch resp[1] {
	case 0x00:
		// без авторизации — ок
	case 0x02:
		if user == "" {
			return nil, fmt.Errorf("SOCKS5-прокси требует логин/пароль, а они не заданы (auth=true, но user/pass пустые)")
		}
		req := []byte{0x01, byte(len(user))}
		req = append(req, []byte(user)...)
		req = append(req, byte(len(pass)))
		req = append(req, []byte(pass)...)
		if _, err := conn.Write(req); err != nil {
			return nil, fmt.Errorf("SOCKS5: ошибка отправки логина/пароля: %w", err)
		}
		authResp := make([]byte, 2)
		if _, err := io.ReadFull(conn, authResp); err != nil {
			return nil, fmt.Errorf("SOCKS5: ошибка чтения ответа на логин/пароль: %w", err)
		}
		if authResp[1] != 0x00 {
			return nil, fmt.Errorf("SOCKS5: неверный логин/пароль")
		}
	case 0xFF:
		return nil, fmt.Errorf("SOCKS5-прокси не принял ни одного метода аутентификации (возможно, ему нужен логин/пароль, а auth=false в конфиге)")
	default:
		return nil, fmt.Errorf("SOCKS5: сервер выбрал неподдерживаемый метод аутентификации (%d)", resp[1])
	}

	// --- CONNECT ---
	req := []byte{0x05, 0x01, 0x00} // VER, CMD=CONNECT, RSV
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("SOCKS5: слишком длинное доменное имя %q", host)
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("SOCKS5: ошибка отправки CONNECT: %w", err)
	}

	respHead := make([]byte, 4)
	if _, err := io.ReadFull(conn, respHead); err != nil {
		return nil, fmt.Errorf("SOCKS5: ошибка чтения ответа на CONNECT: %w", err)
	}
	if respHead[0] != 0x05 {
		return nil, fmt.Errorf("SOCKS5: неверная версия протокола в ответе (%d)", respHead[0])
	}
	if respHead[1] != 0x00 {
		return nil, fmt.Errorf("SOCKS5: прокси отказал в CONNECT (код %d: %s)", respHead[1], socks5ReplyText(respHead[1]))
	}

	// Дочитываем BND.ADDR + BND.PORT — сами значения не нужны, но байты
	// из соединения выбрать обязательно, иначе следующий Read() унаследует
	// хвост этого ответа.
	switch respHead[3] {
	case 0x01: // IPv4
		if _, err := io.ReadFull(conn, make([]byte, 4+2)); err != nil {
			return nil, fmt.Errorf("SOCKS5: ошибка чтения BND.ADDR (IPv4): %w", err)
		}
	case 0x03: // domain
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return nil, fmt.Errorf("SOCKS5: ошибка чтения длины BND.ADDR: %w", err)
		}
		if _, err := io.ReadFull(conn, make([]byte, int(l[0])+2)); err != nil {
			return nil, fmt.Errorf("SOCKS5: ошибка чтения BND.ADDR (domain): %w", err)
		}
	case 0x04: // IPv6
		if _, err := io.ReadFull(conn, make([]byte, 16+2)); err != nil {
			return nil, fmt.Errorf("SOCKS5: ошибка чтения BND.ADDR (IPv6): %w", err)
		}
	default:
		return nil, fmt.Errorf("SOCKS5: неизвестный тип адреса в ответе (%d)", respHead[3])
	}

	ok = true
	return conn, nil
}

func socks5ReplyText(code byte) string {
	switch code {
	case 0x01:
		return "general SOCKS server failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return "unknown error"
	}
}

// dialViaHTTPProxy устанавливает TCP-соединение до target через
// HTTP-прокси proxyAddr методом CONNECT. user/pass пустые — без
// авторизации (иначе — Proxy-Authorization: Basic).
func dialViaHTTPProxy(proxyAddr, target, user, pass string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("не могу подключиться к HTTP-прокси %s: %w", proxyAddr, err)
	}
	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()

	var authHeader string
	if user != "" {
		cred := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		authHeader = "Proxy-Authorization: Basic " + cred + "\r\n"
	}
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", target, target, authHeader)
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, fmt.Errorf("HTTP-прокси: ошибка отправки CONNECT: %w", err)
	}

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("HTTP-прокси: ошибка чтения ответа: %w", err)
	}
	parts := strings.SplitN(strings.TrimSpace(statusLine), " ", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("HTTP-прокси: некорректный статус-ответ: %q", statusLine)
	}
	if parts[1] != "200" {
		msg := statusLine
		if len(parts) >= 3 {
			msg = parts[2]
		}
		if parts[1] == "407" {
			return nil, fmt.Errorf("HTTP-прокси требует авторизацию, либо логин/пароль неверны (407): %s", msg)
		}
		return nil, fmt.Errorf("HTTP-прокси отказал в CONNECT (%s): %s", parts[1], msg)
	}

	// Дочитываем оставшиеся заголовки до пустой строки.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("HTTP-прокси: ошибка чтения заголовков: %w", err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}

	ok = true
	if br.Buffered() > 0 {
		// Сервер мог прислать что-то ещё в том же TCP-сегменте сразу
		// после заголовков — эти байты уже осели в буфере bufio.Reader,
		// net.Conn сам по себе не умеет вернуть их назад в сокет.
		// bufferedConn отдаёт сначала их, потом уже читает из conn.
		return &bufferedConn{Conn: conn, r: br}, nil
	}
	return conn, nil
}

// bufferedConn — net.Conn, у которого чтение сначала идёт из уже
// прочитанных bufio.Reader байт, а потом — из самого соединения. Нужен
// только для dialViaHTTPProxy (см. комментарий там).
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}
