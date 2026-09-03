//go:build windows && !legacy

package main

import (
	"io"
	"log"
	"os/exec"
	"strings"

	"github.com/gliderlabs/ssh"
	"github.com/qsocket/conpty-go"
)

// sessionHandler — обработчик обычной ssh-сессии (не sftp) на Windows.
// Если клиент запросил PTY (интерактивный терминал) — поднимаем cmd.exe
// через настоящий ConPTY, с проброс размера окна и его изменений.
// Если PTY не запрошен (например, "ssh host команда") — просто выполняем
// команду без псевдотерминала, это не требует ConPTY вообще.
func sessionHandler(s ssh.Session) {
	ptyReq, winCh, isPty := s.Pty()

	if !isPty {
		runPlain(s)
		return
	}

	// qsocket/conpty-go требует Windows 10 build 1809+
	// На старых версиях просто не будет работать
	cpty, err := conpty.Start("cmd.exe")
	if err != nil {
		log.Println("sshd: не удалось поднять ConPTY:", err)
		io.WriteString(s, "Не удалось запустить шелл: "+err.Error()+"\r\nНужен Windows 10 1809+ для ConPTY.\r\n")
		s.Exit(1)
		return
	}
	defer cpty.Close()

	// Установить начальный размер окна
	cpty.Resize(uint16(ptyReq.Window.Width), uint16(ptyReq.Window.Height))

	// ssh-клиент -> cmd.exe
	go io.Copy(cpty, s)
	// cmd.exe -> ssh-клиент
	go io.Copy(s, cpty)

	// изменения размера окна (например, растянул терминал) прокидываем в ConPTY
	go func() {
		for win := range winCh {
			cpty.Resize(uint16(win.Width), uint16(win.Height))
		}
	}()

	// qsocket/conpty-go не предоставляет удобный Wait(),
	// поэтому просто держим соединение открытым
	// Когда процесс завершится, io.Copy завершит работу
	s.Exit(0)
}

// runPlain выполняет одну команду без псевдотерминала — как обычный
// "ssh host команда" в скриптах. ConPTY тут не нужен, это просто процесс
// с перенаправленным вводом/выводом.
func runPlain(s ssh.Session) {
	cmdline := strings.Join(s.Command(), " ")
	if cmdline == "" {
		io.WriteString(s, "PTY не запрошен и команда не указана — сделай ssh -t для интерактивного шелла.\r\n")
		s.Exit(1)
		return
	}
	cmd := exec.Command("cmd.exe", "/c", cmdline)
	cmd.Stdin = s
	cmd.Stdout = s
	cmd.Stderr = s.Stderr()
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			s.Exit(exitErr.ExitCode())
			return
		}
		io.WriteString(s.Stderr(), err.Error()+"\r\n")
		s.Exit(1)
		return
	}
	s.Exit(0)
}
