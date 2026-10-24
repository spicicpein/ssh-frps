package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/gofrp/tiny-frpc/pkg/config"
	toml "github.com/pelletier/go-toml/v2"
)

const testEgressConfig = `
serverAddr = "vds.example.com"
serverPort = 2200
auth.token = "tok"
winsshPassword = "p"
shellDir = "C:\\Users\\x"
egressSocksAuth = true
egressSocksUser = "emp"
egressSocksPass = "secret"
egressShadowsocksMethod = "aes-256-gcm"
egressShadowsocksPassword = "sspass"

[[proxies]]
name = "winssh"
type = "tcp"
winssh = true
localPort = 2002
remotePort = 65000

[[proxies]]
name = "egress-socks"
type = "tcp"
egressSocks = true
localPort = 1080
remotePort = 65010

[[proxies]]
name = "egress-ss"
type = "tcp"
egressShadowsocks = true
localPort = 1081
remotePort = 65011
`

// Наши собственные поля конфига читаются так, как описано в frpc-example.toml.
func TestEgressConfigParsing(t *testing.T) {
	var e winsshExtra
	if err := toml.Unmarshal([]byte(testEgressConfig), &e); err != nil {
		t.Fatalf("toml: %v", err)
	}
	if got := sshdPort(e); got != 2002 {
		t.Errorf("sshdPort = %d, ожидалось 2002", got)
	}
	if got := egressSocksPort(e); got != 1080 {
		t.Errorf("egressSocksPort = %d, ожидалось 1080", got)
	}
	if got := egressShadowsocksPort(e); got != 1081 {
		t.Errorf("egressShadowsocksPort = %d, ожидалось 1081", got)
	}
	if !e.EgressSocksAuth || e.EgressSocksUser != "emp" || e.EgressSocksPass != "secret" {
		t.Errorf("настройки авторизации SOCKS прочитаны неверно: %+v", e)
	}
	if e.EgressShadowsocksMethod != "aes-256-gcm" || e.EgressShadowsocksPassword != "sspass" {
		t.Errorf("настройки Shadowsocks прочитаны неверно: %+v", e)
	}
}

// Наши флаги внутри [[proxies]] (winssh/egressSocks/egressShadowsocks) не
// должны мешать загрузчику tiny-frpc: все три прокси должны зарегистрироваться
// на frps с правильными портами.
func TestEgressProxiesRegisterWithFrp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "frpc.toml")
	if err := os.WriteFile(path, []byte(testEgressConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, proxyCfgs, visitorCfgs, _, err := config.LoadClientConfig(path, false)
	if err != nil {
		t.Fatalf("LoadClientConfig: %v", err)
	}
	params := config.ParseFRPCConfigToGoSSHParam(cfg, proxyCfgs, visitorCfgs)
	if len(params) != 3 {
		t.Fatalf("зарегистрировано %d прокси, ожидалось 3", len(params))
	}
	want := map[string]string{"127.0.0.1:2002": "65000", "127.0.0.1:1080": "65010", "127.0.0.1:1081": "65011"}
	for _, p := range params {
		remote, ok := want[p.LocalAddr]
		if !ok {
			t.Errorf("неожиданный LocalAddr %q", p.LocalAddr)
			continue
		}
		if !strings.Contains(p.SSHExtraCmd, "--remote-port "+remote) {
			t.Errorf("для %s ожидался remote-port %s, команда: %q", p.LocalAddr, remote, p.SSHExtraCmd)
		}
		delete(want, p.LocalAddr)
	}
	if len(want) != 0 {
		t.Errorf("не зарегистрированы: %v", want)
	}
}

// Пример из документации обязан быть рабочим: берём сам frpc-example.toml,
// раскомментируем всё из секций 5-6 (egress-настройки и все примеры
// [[proxies]]) и проверяем, что результат читают и наш код, и загрузчик
// tiny-frpc. Ловит, например, настройки egress, оказавшиеся ниже первого
// [[proxies]] (в TOML они стали бы полями прокси, и программа их не увидела бы).
func TestExampleConfigWithEverythingEnabled(t *testing.T) {
	raw, err := os.ReadFile("frpc-example.toml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	idx := strings.Index(text, "# ── 5. Egress")
	if idx < 0 {
		t.Fatal("в frpc-example.toml нет секции 5 (Egress)")
	}
	re := regexp.MustCompile(`(?m)^# ((?:egress\w+ = .*)|(?:\[\[proxies\]\])|(?:name = .*)|(?:type = .*)|(?:localPort = .*)|(?:remotePort = .*))$`)
	enabled := text[:idx] + re.ReplaceAllString(text[idx:], "$1")

	var e winsshExtra
	if err := toml.Unmarshal([]byte(enabled), &e); err != nil {
		t.Fatalf("toml: %v", err)
	}
	if got := sshdPort(e); got != 2222 {
		t.Errorf("sshdPort = %d, ожидалось 2222", got)
	}
	if got := egressSocksPort(e); got != 1080 {
		t.Errorf("egressSocksPort = %d, ожидалось 1080 (настройки egress ниже [[proxies]]?)", got)
	}
	if got := egressShadowsocksPort(e); got != 1081 {
		t.Errorf("egressShadowsocksPort = %d, ожидалось 1081", got)
	}
	if !e.EgressSocksAuth || e.EgressSocksUser == "" || e.EgressSocksPass == "" {
		t.Errorf("настройки авторизации SOCKS не прочитаны: %+v", e)
	}
	if e.EgressShadowsocksPassword == "" {
		t.Errorf("пароль Shadowsocks не прочитан: %+v", e)
	}

	path := filepath.Join(t.TempDir(), "frpc.toml")
	if err := os.WriteFile(path, []byte(enabled), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, proxyCfgs, visitorCfgs, _, err := config.LoadClientConfig(path, false)
	if err != nil {
		t.Fatalf("tiny-frpc не принял пример: %v", err)
	}
	// ssh + rdp + smb + egress-socks + egress-ss + произвольный сервис
	if n := len(config.ParseFRPCConfigToGoSSHParam(cfg, proxyCfgs, visitorCfgs)); n != 6 {
		t.Errorf("зарегистрировано %d прокси, ожидалось 6", n)
	}
}
