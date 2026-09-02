//go:build windows && legacy

package main

import (
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/gliderlabs/ssh"
	"github.com/iamacarpet/go-winpty"
)

// dllDir — папка, где лежат winpty.dll и winpty-agent.exe. Ищем рядом с самим
// exe (os.Executable), а не полагаемся на текущую рабочую директорию — так
// работает независимо от того, откуда программу запустили (двойной клик,
// планировщик задач, служба).
func dllDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

// sessionHandler — версия для старых Windows (Server 2008R2/Win7 и новее),
// где ConPTY ещё не существует (появился в 1809/Server 2019). Вместо него —
// winpty: рабочий, десятилетиями проверенный обходной путь, который получает
// настоящий терминал (цвета, курсор, интерактивные программы) через скрытое
// консольное окно, а не голые пайпы без терминальной семантики. Нужны два
// файла рядом с exe: winpty.dll и winpty-agent.exe (не встроены сознательно —
// чтобы антивирусы не видели самораспаковывающийся exe и не ругались).
func sessionHandler(s ssh.Session) {
	ptyReq, winCh, isPty := s.Pty()

	if !isPty {
		runPlain(s)
		return
	}

	dir := dllDir()
	if _, err := os.Stat(filepath.Join(dir, "winpty.dll")); err != nil {
		log.Println("sshd: winpty.dll не найден рядом с программой:", err)
		io.WriteString(s, "Не найден winpty.dll рядом с программой — интерактивный шелл недоступен.\r\n")
		s.Exit(1)
		return
	}

	wp, err := winpty.OpenWithOptions(winpty.Options{
		DLLPrefix:   dir,
		Command:     "cmd.exe",
		Dir:         dir,
		Env:         os.Environ(),
		InitialCols: uint32(ptyReq.Window.Width),
		InitialRows: uint32(ptyReq.Window.Height),
	})
	if err != nil {
		log.Println("sshd: не удалось поднять winpty:", err)
		io.WriteString(s, "Не удалось запустить шелл: "+err.Error()+"\r\n")
		s.Exit(1)
		return
	}
	defer wp.Close()

	// ssh-клиент -> cmd.exe
	go io.Copy(wp.StdIn, s)
	// cmd.exe -> ssh-клиент
	go io.Copy(s, wp.StdOut)

	go func() {
		for win := range winCh {
			wp.SetSize(uint32(win.Width), uint32(win.Height))
		}
	}()

	// у go-winpty нет удобного Wait() с кодом завершения — просто держим
	// сессию, пока процесс жив, ориентируясь на процесс-хендл.
	proc, err := os.FindProcess(int(wp.GetProcHandle()))
	if err == nil {
		proc.Wait()
	}
	s.Exit(0)
}

// runPlain — то же самое, что в современной версии: выполнение одной
// команды без псевдотерминала, ConPTY/winpty тут не нужны вообще.
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

