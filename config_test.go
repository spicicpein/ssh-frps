package main

import (
	"os"
	"path/filepath"
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
