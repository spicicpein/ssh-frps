//go:build !windows

package main

import (
	"io"
	"os/exec"

	"github.com/gliderlabs/ssh"
)

// sessionHandler для НЕ-Windows сборок. Реального ConPTY-эквивалента тут
// нет и не нужен — этот файл существует только для того, чтобы я мог
// собирать и живьём тестировать протокольную часть (авторизация, sftp,
// туннель) на linux в песочнице. В поставку под Windows этот файл вообще
// не попадает — сборка идёт из shell_windows.go, см. GOOS=windows.
func sessionHandler(s ssh.Session) {
	cmd := exec.Command("/bin/sh")
	cmd.Stdin = s
	cmd.Stdout = s
	cmd.Stderr = s.Stderr()
	if err := cmd.Run(); err != nil {
		io.WriteString(s.Stderr(), err.Error()+"\n")
		s.Exit(1)
		return
	}
	s.Exit(0)
}
