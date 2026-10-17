package main

import (
	"bufio"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-gost/go-shadowsocks2/core"
	"github.com/go-gost/go-shadowsocks2/socks"
	ssutils "github.com/go-gost/go-shadowsocks2/utils"

	"github.com/gofrp/tiny-frpc/pkg/util"
)

// ═══════════════════════════════════════════════════════════════════════
//  Egress: winssh-tunnel сам становится точкой выхода в интернет —
//  SOCKS5/HTTP-прокси и/или Shadowsocks-сервер, доступные снаружи через
//  собственный [[proxies]] в frpc.toml (флаги egressSocks/
//  egressShadowsocks). Каждый — на своём порту, включаются независимо
//  друг от друга.
// ═══════════════════════════════════════════════════════════════════════

// egressThrottle защищает авторизацию egress-прокси от перебора (см. throttle
// в main.go — там же оговорка про то, что через frp все клиенты выглядят как
// 127.0.0.1).
var egressThrottle = newThrottle()

// egressAuth выполняет проверку учётных данных под троттлингом. check
// вызывается только после выдержанной задержки и должен сравнивать данные за
// постоянное время. tooMany=true — слишком много параллельных попыток.
func egressAuth(w net.Conn, check func() bool) (good, tooMany bool) {
	remote := w.RemoteAddr().String()
	release, allowed := egressThrottle.enter(remote)
	if !allowed {
		return false, true
	}
	defer release()
	// Задержка могла быть долгой — продлеваем дедлайн хендшейка.
	_ = w.SetReadDeadline(time.Now().Add(15 * time.Second))
	good = check()
	egressThrottle.record(remote, good)
	return good, false
}

// ── SOCKS5/HTTP (один порт, протокол определяется автоматически по
//    первому байту соединения) ──────────────────────────────────────────

func startEgressSocksServer(port int, authRequired bool, user, pass string) {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("egress SOCKS5/HTTP: не смог занять порт %d: %v", port, err)
		return
	}
	log.Printf("egress SOCKS5/HTTP слушает на %s (авторизация: %v)", addr, authRequired)
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("egress SOCKS5/HTTP: ошибка accept: %v", err)
			return
		}
		go handleEgressSocksConn(conn, authRequired, user, pass)
	}
}

func handleEgressSocksConn(conn net.Conn, authRequired bool, user, pass string) {
	defer conn.Close()

	// Таймаут только на хендшейк — не хотим, чтобы зависшие/медленные
	// клиенты копили горутины навсегда. После хендшейка снимается.
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))

	br := bufio.NewReader(conn)
	first, err := br.Peek(1)
	if err != nil {
		return
	}

	var target string
	if first[0] == 0x05 {
		target, err = socks5ServerHandshake(br, conn, authRequired, user, pass)
	} else {
		target, err = httpConnectServerHandshake(br, conn, authRequired, user, pass)
	}
	if err != nil {
		log.Printf("egress SOCKS5/HTTP: хендшейк не удался (%s): %v", conn.RemoteAddr(), err)
		return
	}

	_ = conn.SetReadDeadline(time.Time{}) // снимаем таймаут для основной передачи данных

	upstream, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Printf("egress SOCKS5/HTTP: не смог подключиться к %s: %v", target, err)
		return
	}
	defer upstream.Close()

	// bufferedConn (см. tunnel.go) — на случай, если клиент прислал
	// что-то сверх хендшейка в том же TCP-сегменте, эти байты уже осели
	// в br и их нельзя терять.
	clientSide := &bufferedConn{Conn: conn, r: br}
	_, _ = util.Join(clientSide, upstream)
}

// socks5ServerHandshake — серверная сторона SOCKS5 (RFC 1928) с опциональной
// авторизацией логин/пароль (RFC 1929). Поддерживается только CONNECT —
// BIND и UDP ASSOCIATE не нужны для нашей задачи (проброс произвольного
// TCP наружу).
func socks5ServerHandshake(r *bufio.Reader, w net.Conn, authRequired bool, user, pass string) (string, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(r, head); err != nil {
		return "", err
	}
	if head[0] != 0x05 {
		return "", fmt.Errorf("не SOCKS5 (ver=%d)", head[0])
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(r, methods); err != nil {
		return "", err
	}

	wantMethod := byte(0x00)
	if authRequired {
		wantMethod = 0x02
	}
	offered := false
	for _, m := range methods {
		if m == wantMethod {
			offered = true
			break
		}
	}
	if !offered {
		_, _ = w.Write([]byte{0x05, 0xFF})
		return "", fmt.Errorf("клиент не предложил нужный метод аутентификации (нужен %d)", wantMethod)
	}
	if _, err := w.Write([]byte{0x05, wantMethod}); err != nil {
		return "", err
	}

	if authRequired {
		ah := make([]byte, 2)
		if _, err := io.ReadFull(r, ah); err != nil {
			return "", err
		}
		if ah[0] != 0x01 {
			return "", fmt.Errorf("неверная версия субнегоциации (%d)", ah[0])
		}
		uname := make([]byte, int(ah[1]))
		if _, err := io.ReadFull(r, uname); err != nil {
			return "", err
		}
		plenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, plenBuf); err != nil {
			return "", err
		}
		passBuf := make([]byte, int(plenBuf[0]))
		if _, err := io.ReadFull(r, passBuf); err != nil {
			return "", err
		}
		good, tooMany := egressAuth(w, func() bool {
			u := subtle.ConstantTimeCompare(uname, []byte(user))
			p := subtle.ConstantTimeCompare(passBuf, []byte(pass))
			return u&p == 1
		})
		if tooMany {
			_, _ = w.Write([]byte{0x01, 0x01})
			return "", fmt.Errorf("слишком много одновременных попыток авторизации")
		}
		if !good {
			_, _ = w.Write([]byte{0x01, 0x01})
			return "", fmt.Errorf("неверный логин/пароль")
		}
		if _, err := w.Write([]byte{0x01, 0x00}); err != nil {
			return "", err
		}
	}

	// VER CMD RSV ATYP DST.ADDR DST.PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(r, req); err != nil {
		return "", err
	}
	if req[1] != 0x01 { // только CmdConnect
		_, _ = w.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return "", fmt.Errorf("поддерживается только CONNECT (получено cmd=%d)", req[1])
	}

	var host string
	switch req[3] {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case 0x03: // domain
		lb := make([]byte, 1)
		if _, err := io.ReadFull(r, lb); err != nil {
			return "", err
		}
		hb := make([]byte, int(lb[0]))
		if _, err := io.ReadFull(r, hb); err != nil {
			return "", err
		}
		host = string(hb)
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	default:
		_, _ = w.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return "", fmt.Errorf("неизвестный ATYP %d", req[3])
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return "", err
	}
	port := int(portBuf[0])<<8 | int(portBuf[1])

	if _, err := w.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return "", err
	}

	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

// httpConnectServerHandshake — серверная сторона HTTP CONNECT с опциональной
// Basic-авторизацией. Поддерживается только CONNECT (туннелирование
// произвольного TCP, в первую очередь HTTPS) — обычный HTTP-проксирование
// GET/POST с абсолютным URI не реализовано, см. README.
func httpConnectServerHandshake(r *bufio.Reader, w net.Conn, authRequired bool, user, pass string) (string, error) {
	reqLine, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	parts := strings.Fields(reqLine)
	if len(parts) < 2 {
		return "", fmt.Errorf("некорректная строка запроса: %q", strings.TrimSpace(reqLine))
	}
	method := strings.ToUpper(parts[0])
	target := parts[1]

	var gotAuth string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return "", err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if idx := strings.Index(line, ":"); idx > 0 {
			if strings.ToLower(strings.TrimSpace(line[:idx])) == "proxy-authorization" {
				gotAuth = strings.TrimSpace(line[idx+1:])
			}
		}
	}

	if authRequired {
		expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
		good, tooMany := egressAuth(w, func() bool {
			return subtle.ConstantTimeCompare([]byte(gotAuth), []byte(expected)) == 1
		})
		if tooMany {
			_, _ = io.WriteString(w, "HTTP/1.1 429 Too Many Requests\r\n\r\n")
			return "", fmt.Errorf("слишком много одновременных попыток авторизации")
		}
		if !good {
			_, _ = io.WriteString(w, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"winssh-tunnel\"\r\n\r\n")
			return "", fmt.Errorf("неверная или отсутствующая авторизация")
		}
	}

	if method != "CONNECT" {
		_, _ = io.WriteString(w, "HTTP/1.1 405 Method Not Allowed\r\n\r\n")
		return "", fmt.Errorf("поддерживается только CONNECT (получено %s)", method)
	}

	host := target
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	if _, err := io.WriteString(w, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return "", err
	}
	return host, nil
}

// ── Shadowsocks (github.com/go-gost/go-shadowsocks2) ────────────────────

// egressShadowsocksMethods — поддерживаемые шифры. Максимально
// универсальный набор классических AEAD (совместимы почти со всеми
// существующими Shadowsocks-клиентами, от старых мобильных приложений до
// shadowsocks-rust) — без более новых SIP022/SS2022 вариантов, чтобы не
// плодить экзотику ради экзотики. aes-256-gcm — обязателен и является
// дефолтом.
var egressShadowsocksMethods = map[string]bool{
	"aes-256-gcm":            true,
	"aes-128-gcm":            true,
	"chacha20-ietf-poly1305": true,
}

func startEgressShadowsocksServer(port int, method, password string) {
	if method == "" {
		method = "aes-256-gcm"
	}
	if !egressShadowsocksMethods[strings.ToLower(method)] {
		log.Printf("egress Shadowsocks: неизвестный/неподдерживаемый шифр %q (доступны: aes-256-gcm, aes-128-gcm, chacha20-ietf-poly1305)", method)
		return
	}
	if password == "" {
		log.Printf("egress Shadowsocks: egressShadowsocksPassword не задан в frpc.toml — сервер не запущен")
		return
	}

	cipher, err := ssutils.PickCipher(method, password)
	if err != nil {
		log.Printf("egress Shadowsocks: не смог создать шифр %q: %v", method, err)
		return
	}

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("egress Shadowsocks: не смог занять порт %d: %v", port, err)
		return
	}
	log.Printf("egress Shadowsocks (%s) слушает на %s", method, addr)

	server := core.NewTCPServer(core.ServerConfig{Cipher: cipher})

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("egress Shadowsocks: ошибка accept: %v", err)
			return
		}
		go handleEgressShadowsocksConn(conn, &server)
	}
}

func handleEgressShadowsocksConn(conn net.Conn, server *core.TCPServer) {
	defer func() {
		// Защита от активных проб (шлют по байту, смотрят сколько сервер
		// съест перед закрытием, чтобы отличить Shadowsocks от случайного
		// шума) — тот же приём, что в эталонной реализации библиотеки.
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		_, _ = io.Copy(io.Discard, conn)
		conn.Close()
	}()

	sc, err := server.WrapConn(conn)
	if err != nil {
		log.Printf("egress Shadowsocks: WrapConn: %v", err)
		return
	}

	tc, ok := sc.(interface{ Target() socks.Addr })
	if !ok {
		log.Printf("egress Shadowsocks: не смог получить целевой адрес")
		return
	}
	target := tc.Target()
	if len(target) == 0 {
		// Обычно значит: неверный пароль/шифр у клиента, либо это вообще
		// не Shadowsocks-клиент, а случайное/сканирующее соединение.
		log.Printf("egress Shadowsocks: пустой целевой адрес от %s (неверный пароль/шифр или проба?)", conn.RemoteAddr())
		return
	}

	upstream, err := net.DialTimeout("tcp", target.String(), 10*time.Second)
	if err != nil {
		log.Printf("egress Shadowsocks: не смог подключиться к %s: %v", target, err)
		return
	}
	defer upstream.Close()

	_, _ = util.Join(sc, upstream)
}
