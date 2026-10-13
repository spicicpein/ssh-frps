//go:build windows && legacy

package main

import (
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/iamacarpet/go-winpty"
	"golang.org/x/sys/windows"
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
		failSession(s, "Не найден winpty.dll рядом с программой — интерактивный шелл недоступен.\r\n")
		return
	}

	startDir := dir
	if shellStartDir != "" {
		startDir = shellStartDir
	}
	if st, err := os.Stat(startDir); err != nil || !st.IsDir() {
		log.Printf("sshd: стартовая папка шелла недоступна: %q (%v)", startDir, err)
		failSession(s, "Стартовая папка шелла не существует: "+startDir+"\r\nПроверь shellDir в frpc.toml.\r\n")
		return
	}
	log.Printf("sshd: запускаю cmd.exe через winpty, папка %q", startDir)
	wp, err := winpty.OpenWithOptions(winpty.Options{
		DLLPrefix:   dir,
		Command:     "cmd.exe",
		Dir:         startDir,
		Env:         os.Environ(),
		InitialCols: uint32(ptyReq.Window.Width),
		InitialRows: uint32(ptyReq.Window.Height),
	})
	if err != nil {
		log.Println("sshd: не удалось поднять winpty:", err)
		failSession(s, "Не удалось запустить шелл: "+err.Error()+"\r\n")
		return
	}
	defer wp.Close()

	// Та же причина кракозябр, что и в modern-версии (shell_windows_modern.go):
	// cmd.exe по умолчанию пишет в OEM-кодировке консоли, а SSH-клиент
	// ждёт UTF-8. Здесь (в отличие от modern) wp.StdIn — это io.Writer, а
	// не io.Reader, который можно обернуть в MultiReader, поэтому просто
	// пишем chcp напрямую, ДО того как запустить проброс реального ввода
	// пользователя.
	_, _ = wp.StdIn.Write([]byte("chcp 65001>nul\r\n"))

	// Все процессы сессии (cmd.exe, winpty-agent.exe и всё, что пользователь
	// запустит из шелла) — в Job Object с KILL_ON_JOB_CLOSE: что бы ни
	// случилось с сессией, после выхода из функции в системе не остаётся
	// зомби. Регистрируется ПОСЛЕ defer wp.Close(), поэтому выполнится раньше.
	job := newKillJob()
	defer job.kill()
	h := windows.Handle(wp.GetProcHandle())
	ah := windows.Handle(wp.AgentProcessHandle())
	job.add(h, "cmd.exe")
	job.add(ah, "winpty-agent.exe")

	// ssh-клиент -> cmd.exe. Канал stdinDone закрывается, когда клиент
	// закрыл ввод (EOF/закрытие канала) — это второй признак ухода клиента.
	stdinDone := make(chan struct{})
	go func() {
		io.Copy(wp.StdIn, s)
		close(stdinDone)
	}()
	// cmd.exe -> ssh-клиент. Канал outDone нужен, чтобы после завершения
	// процесса дочитать хвост вывода, а не обрезать его раньше времени.
	outDone := make(chan struct{})
	go func() {
		io.Copy(s, wp.StdOut)
		close(outDone)
	}()

	go func() {
		for win := range winCh {
			wp.SetSize(uint32(win.Width), uint32(win.Height))
		}
	}()

	// Ждём завершения cmd.exe по его HANDLE (os.FindProcess тут не годится —
	// он принимает PID, а не HANDLE).
	procDone := make(chan uint32, 1)
	go func() {
		var code uint32
		if ev, err := windows.WaitForSingleObject(h, windows.INFINITE); err != nil || ev != windows.WAIT_OBJECT_0 {
			log.Printf("sshd: не удалось дождаться завершения шелла (event=%d): %v", ev, err)
		} else if err := windows.GetExitCodeProcess(h, &code); err != nil {
			log.Println("sshd: не удалось получить код завершения шелла:", err)
		}
		procDone <- code
	}()

	// Ждём ЛИБО выхода шелла (exit), ЛИБО ухода клиента (закрыл окно/обрыв
	// связи). Раньше ждали только первого — при закрытии окна обработчик
	// висел вечно, а cmd.exe и winpty-agent.exe оставались в системе.
	var code uint32
	exited := false
	select {
	case code = <-procDone:
		exited = true
	case <-s.Context().Done():
		log.Printf("sshd: клиент %s отключился — завершаю шелл", s.RemoteAddr())
	case <-stdinDone:
		log.Printf("sshd: клиент %s закрыл ввод — завершаю шелл", s.RemoteAddr())
	}
	if !exited {
		// Если шелл как раз завершается сам — даём ему доиграть, иначе убиваем.
		select {
		case code = <-procDone:
			exited = true
		case <-time.After(500 * time.Millisecond):
		}
	}

	if exited {
		// Обычный выход: дочитываем остаток вывода (агент закроет pipe после
		// выхода процесса), но не вечно — на случай зависшего агента.
		select {
		case <-outDone:
		case <-time.After(2 * time.Second):
		}
		s.Exit(int(code))
		return // defer: job.kill() добьёт оставшихся потомков, затем wp.Close()
	}

	// Клиент ушёл, шелл жив — убиваем явно (Job Object — страховка сверху).
	_ = windows.TerminateProcess(h, 1)
	if ah != 0 {
		_ = windows.TerminateProcess(ah, 1)
	}
	job.kill()
	// Дождаться, пока горутина ожидания увидит смерть процесса, — иначе
	// wp.Close() закроет хендл прямо под её WaitForSingleObject.
	select {
	case <-procDone:
	case <-time.After(3 * time.Second):
	}
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
	// Та же история с кракозябрами, что в интерактивном режиме — cmd.exe
	// пишет в OEM-кодировке, SSH-клиент ждёт UTF-8. chcp>nul && ... не
	// оставляет служебного вывода, только результат самой команды.
	cmd := exec.Command("cmd.exe", "/c", "chcp 65001>nul && "+cmdline)
	if shellStartDir != "" {
		cmd.Dir = shellStartDir
	}
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
