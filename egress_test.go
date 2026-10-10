package main

import (
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/go-gost/go-shadowsocks2/core"
	"github.com/go-gost/go-shadowsocks2/socks"
	ssutils "github.com/go-gost/go-shadowsocks2/utils"
)

// TestMain отключает глобальный bloom-фильтр защиты от replay-атак ПЕРЕД
// запуском любых тестов (синглтон инициализируется один раз через
// sync.Once, так что делать это внутри отдельного теста уже поздно, если
// более ранний тест успел его создать первым). В наших тестах клиент и
// сервер Shadowsocks работают в ОДНОМ процессе — без этого собственная
// соль клиента ошибочно засчитывается как "уже виденная", когда её же
// проверяет сервер (тот же самый глобальный фильтр). Сама библиотека
// делает то же самое в своих тестах, см.
// shadowaead/session_manager_test.go. В реальной эксплуатации клиент и
// сервер — разные процессы/машины с независимым состоянием фильтра, это
// чисто тестовый артефакт.
func TestMain(m *testing.M) {
	os.Setenv("SHADOWSOCKS_SF_CAPACITY", "-1")
	os.Exit(m.Run())
}

// startTestEchoServer — простой TCP-эхо-сервер, имитирующий "интернет"
// (сайт, к которому подключается клиент через наш egress-прокси).
func startTestEchoServer(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo server listen: %v", err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go io.Copy(c, c)
		}
	}()
	t.Cleanup(func() { l.Close() })
	return l.Addr().String()
}

func roundtripCheck(t *testing.T, conn net.Conn, label string) {
	t.Helper()
	defer conn.Close()
	msg := []byte("hello-" + label)
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("%s: write: %v", label, err)
	}
	buf := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("%s: read: %v", label, err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("%s: mismatch: got %q want %q", label, buf, msg)
	}
}

// ── SOCKS5/HTTP egress ────────────────────────────────────────────────

func startTestEgressSocks(t *testing.T, authRequired bool, user, pass string) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("egress socks listen: %v", err)
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go handleEgressSocksConn(conn, authRequired, user, pass)
		}
	}()
	t.Cleanup(func() { l.Close() })
	return l.Addr().String()
}

func TestEgressSocks5NoAuth(t *testing.T) {
	echoAddr := startTestEchoServer(t)
	proxyAddr := startTestEgressSocks(t, false, "", "")

	conn, err := dialViaSOCKS5(proxyAddr, echoAddr, "", "")
	if err != nil {
		t.Fatalf("dialViaSOCKS5: %v", err)
	}
	roundtripCheck(t, conn, "socks5-noauth")
}

func TestEgressSocks5WithAuth(t *testing.T) {
	echoAddr := startTestEchoServer(t)
	proxyAddr := startTestEgressSocks(t, true, "myuser", "mypass")

	conn, err := dialViaSOCKS5(proxyAddr, echoAddr, "myuser", "mypass")
	if err != nil {
		t.Fatalf("dialViaSOCKS5 with correct auth: %v", err)
	}
	roundtripCheck(t, conn, "socks5-auth-ok")
}

func TestEgressSocks5WrongPassword(t *testing.T) {
	echoAddr := startTestEchoServer(t)
	proxyAddr := startTestEgressSocks(t, true, "myuser", "mypass")

	_, err := dialViaSOCKS5(proxyAddr, echoAddr, "myuser", "WRONG")
	if err == nil {
		t.Fatal("expected error with wrong password, got nil")
	}
}

func TestEgressSocks5MissingAuthWhenRequired(t *testing.T) {
	echoAddr := startTestEchoServer(t)
	proxyAddr := startTestEgressSocks(t, true, "myuser", "mypass")

	_, err := dialViaSOCKS5(proxyAddr, echoAddr, "", "")
	if err == nil {
		t.Fatal("expected error when auth required but not provided, got nil")
	}
}

func TestEgressHTTPConnectNoAuth(t *testing.T) {
	echoAddr := startTestEchoServer(t)
	proxyAddr := startTestEgressSocks(t, false, "", "")

	conn, err := dialViaHTTPProxy(proxyAddr, echoAddr, "", "")
	if err != nil {
		t.Fatalf("dialViaHTTPProxy: %v", err)
	}
	roundtripCheck(t, conn, "http-connect-noauth")
}

func TestEgressHTTPConnectWithAuth(t *testing.T) {
	echoAddr := startTestEchoServer(t)
	proxyAddr := startTestEgressSocks(t, true, "myuser", "mypass")

	conn, err := dialViaHTTPProxy(proxyAddr, echoAddr, "myuser", "mypass")
	if err != nil {
		t.Fatalf("dialViaHTTPProxy with correct auth: %v", err)
	}
	roundtripCheck(t, conn, "http-connect-auth-ok")
}

func TestEgressHTTPConnectWrongPassword(t *testing.T) {
	echoAddr := startTestEchoServer(t)
	proxyAddr := startTestEgressSocks(t, true, "myuser", "mypass")

	_, err := dialViaHTTPProxy(proxyAddr, echoAddr, "myuser", "WRONG")
	if err == nil {
		t.Fatal("expected error with wrong password, got nil")
	}
}

// Один порт должен обслуживать ОБА протокола одновременно (детект по
// первому байту) — проверяем, что SOCKS5 и HTTP CONNECT работают на
// одном и том же слушателе без конфликтов.
func TestEgressSocksAndHTTPSamePort(t *testing.T) {
	echoAddr := startTestEchoServer(t)
	proxyAddr := startTestEgressSocks(t, false, "", "")

	c1, err := dialViaSOCKS5(proxyAddr, echoAddr, "", "")
	if err != nil {
		t.Fatalf("socks5 on shared port: %v", err)
	}
	roundtripCheck(t, c1, "shared-port-socks5")

	c2, err := dialViaHTTPProxy(proxyAddr, echoAddr, "", "")
	if err != nil {
		t.Fatalf("http on shared port: %v", err)
	}
	roundtripCheck(t, c2, "shared-port-http")
}

// ── Shadowsocks egress ───────────────────────────────────────────────

func startTestEgressShadowsocks(t *testing.T, method, password string) string {
	t.Helper()
	cipher, err := ssutils.PickCipher(method, password)
	if err != nil {
		t.Fatalf("PickCipher: %v", err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("egress ss listen: %v", err)
	}
	server := core.NewTCPServer(core.ServerConfig{Cipher: cipher})
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go handleEgressShadowsocksConn(conn, &server)
		}
	}()
	t.Cleanup(func() { l.Close() })
	return l.Addr().String()
}

func dialTestShadowsocksClient(t *testing.T, ssAddr, method, password, target string) net.Conn {
	t.Helper()
	cipher, err := ssutils.PickCipher(method, password)
	if err != nil {
		t.Fatalf("PickCipher (client): %v", err)
	}
	client := core.NewTCPClient(core.ClientConfig{Cipher: cipher})
	ap, err := netip.ParseAddrPort(ssAddr)
	if err != nil {
		t.Fatalf("ParseAddrPort: %v", err)
	}
	conn, err := client.Dial(socks.ParseAddr(target), ap)
	if err != nil {
		t.Fatalf("shadowsocks client Dial: %v", err)
	}
	return conn
}

func TestEgressShadowsocksAES256GCM(t *testing.T) {
	echoAddr := startTestEchoServer(t)
	ssAddr := startTestEgressShadowsocks(t, "aes-256-gcm", "correct-password")

	conn := dialTestShadowsocksClient(t, ssAddr, "aes-256-gcm", "correct-password", echoAddr)
	roundtripCheck(t, conn, "shadowsocks-aes256gcm")
}

func TestEgressShadowsocksChacha20(t *testing.T) {
	echoAddr := startTestEchoServer(t)
	ssAddr := startTestEgressShadowsocks(t, "chacha20-ietf-poly1305", "another-password")

	conn := dialTestShadowsocksClient(t, ssAddr, "chacha20-ietf-poly1305", "another-password", echoAddr)
	roundtripCheck(t, conn, "shadowsocks-chacha20")
}

func TestEgressShadowsocksWrongPassword(t *testing.T) {
	echoAddr := startTestEchoServer(t)
	ssAddr := startTestEgressShadowsocks(t, "aes-256-gcm", "correct-password")

	conn := dialTestShadowsocksClient(t, ssAddr, "aes-256-gcm", "WRONG-password", echoAddr)
	defer conn.Close()

	// С неверным паролем AEAD-расшифровка на сервере не пройдёт — сервер
	// просто закроет соединение, не ответив ничего осмысленного.
	conn.Write([]byte("test"))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4)
	_, err := io.ReadFull(conn, buf)
	if err == nil {
		t.Fatal("expected connection to fail/close with wrong password, got successful read")
	}
}
