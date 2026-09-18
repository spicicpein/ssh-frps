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
// через настоящий ConPTY, с пробросом размера окна и его изменений.
// Без реального ConPTY (голые pipe'ы) cmd.exe ведёт себя как при чтении
// batch-скрипта — построчным эхом, без посимвольного интерактивного ввода,
// поэтому набирать что-либо с клавиатуры не получается. ConPTY даёт
// настоящую консоль, как при обычном локальном логине.
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

	// cmd.exe по умолчанию пишет в OEM-кодировке консоли (обычно CP866 на
	// русской Windows), а SSH-клиенты (PuTTY/KiTTY и т.д.) чаще всего ждут
	// UTF-8 — отсюда кракозябры на кириллице. Переключаем кодовую страницу
	// сразу после старта. ПЕРВЫЕ ДВЕ СТРОКИ баннера ("Microsoft Windows
	// [Version...]" и copyright) cmd.exe успевает напечатать ДО того, как
	// прочитает эту команду — они могут остаться в старой кодировке разово
	// при каждом подключении, это чисто косметика. Всё, что после —
	// приглашение, вывод команд, реальный ввод — уже корректный UTF-8.
	_, _ = cpty.Write([]byte("chcp 65001>nul\r\n"))

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
	// Та же история с кракозябрами, что в интерактивном режиме — cmd.exe
	// пишет в OEM-кодировке, SSH-клиент ждёт UTF-8. chcp>nul && ... не
	// оставляет служебного вывода, только результат самой команды.
	cmd := exec.Command("cmd.exe", "/c", "chcp 65001>nul && "+cmdline)
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
