//go:build windows && !legacy

package main

import (
	"io"
	"log"
	"os/exec"
	"strings"

	"github.com/gliderlabs/ssh"
)

// sessionHandler — обработчик обычной ssh-сессии (не sftp) на Windows.
// Поддерживает как интерактивные сессии (с PTY), так и одиночные команды.
// Без полноценного ConPTY поддержки пока, но работает везде на Windows.
func sessionHandler(s ssh.Session) {
	ptyReq, winCh, isPty := s.Pty()

	if !isPty {
		runPlain(s)
		return
	}

	// Если запросили PTY но мы его не поддерживаем (пока) —
	// всё равно запускаем cmd, просто без рески/цветов
	runWithPTY(s, ptyReq, winCh)
}

// runWithPTY запускает интерактивный шелл с поддержкой resize (но без полного PTY)
func runWithPTY(s ssh.Session, ptyReq ssh.Pty, winCh <-chan ssh.Window) {
	cmd := exec.Command("cmd.exe")
	// cmd.exe по умолчанию выводит текст в OEM-кодировке консоли (обычно
	// CP866 на русской Windows), а SSH-клиенты (PuTTY/KiTTY и т.д.) чаще
	// всего ждут UTF-8 — отсюда кракозябры на кириллице. "Впрыскиваем"
	// команду переключения кодовой страницы В САМОЕ НАЧАЛО ввода cmd.exe,
	// ДО того как реальные нажатия клавиш пользователя туда попадут —
	// MultiReader читает наш chcp первым, а дальше прозрачно передаёт то,
	// что реально печатает пользователь. ">nul" прячет служебное
	// сообщение "Active code page: 65001", чтобы не мусорить экран.
	cmd.Stdin = io.MultiReader(strings.NewReader("chcp 65001>nul\r\n"), s)
	cmd.Stdout = s
	cmd.Stderr = s.Stderr()

	// Параметры окна применяем (просто игнорируются на сервере, но клиент может их отправлять)
	_ = ptyReq
	go func() {
		for range winCh {
			// Resize не поддерживается без ConPTY, но канал нужно слушать
		}
	}()

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			s.Exit(exitErr.ExitCode())
			return
		}
		log.Println("sshd: ошибка выполнения cmd.exe:", err)
		io.WriteString(s.Stderr(), err.Error()+"\r\n")
		s.Exit(1)
		return
	}
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
