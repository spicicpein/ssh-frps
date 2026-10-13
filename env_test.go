package main

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

func TestExpandWinEnvConcatenated(t *testing.T) {
	t.Setenv("WT_A", "C:")
	t.Setenv("WT_B", `\Users\x`)
	if got := expandWinEnv("%WT_A%%WT_B%"); got != `C:\Users\x` {
		t.Fatalf("got %q", got)
	}
}

func TestExpandWinEnvUnknownLeftAsIs(t *testing.T) {
	if got := expandWinEnv("%WT_NO_SUCH_VAR%"); got != "%WT_NO_SUCH_VAR%" {
		t.Fatalf("got %q", got)
	}
}

// HOMEPATH отсутствует в окружении (как у службы) — должен восстановиться
// из профиля текущей учётной записи, а не остаться буквальным %HOMEPATH%.
func TestExpandWinEnvHomePathFallback(t *testing.T) {
	t.Setenv("HOMEPATH", "")
	os.Unsetenv("HOMEPATH")
	u, err := user.Current()
	if err != nil || u.HomeDir == "" {
		t.Skip("нет домашней папки у текущего пользователя")
	}
	want := strings.TrimPrefix(u.HomeDir, filepath.VolumeName(u.HomeDir))
	if got := expandWinEnv("%HOMEPATH%"); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
