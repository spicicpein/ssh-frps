//go:build windows && !legacy

package main

import (
	"context"
	"io"
	"log"
	"os/exec"
	"strings"

	"github.com/UserExistsError/conpty"
	"github.com/gliderlabs/ssh"
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

	if !conpty.IsConPtyAvailable() {
		log.Println("sshd: ConPTY недоступен на этой версии Windows (нужна Windows 10 1809+)")
		io.WriteString(s, "Эта версия Windows слишком старая для интерактивного шелла (нужен Windows 10 1809+).\r\n")
		s.Exit(1)
		return
	}

	cpty, err := conpty.Start("cmd.exe",
		conpty.ConPtyDimensions(ptyReq.Window.Width, ptyReq.Window.Height),
	)
	if err != nil {
		log.Println("sshd: не удалось поднять ConPTY:", err)
		io.WriteString(s, "Не удалось запустить шелл: "+err.Error()+"\r\n")
		s.Exit(1)
		return
	}
	defer cpty.Close()

	// ssh-клиент -> cmd.exe
	go io.Copy(cpty, s)
	// cmd.exe -> ssh-клиент
	go io.Copy(s, cpty)

	// изменения размера окна (например, растянул терминал) прокидываем в ConPTY
	go func() {
		for win := range winCh {
			cpty.Resize(win.Width, win.Height)
		}
	}()

	code, err := cpty.Wait(context.Background())
	if err != nil {
		log.Println("sshd: ошибка ожидания процесса:", err)
	}
	s.Exit(int(code))
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
