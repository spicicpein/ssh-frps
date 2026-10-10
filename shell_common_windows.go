//go:build windows

package main

import (
	"io"
	"time"

	"github.com/gliderlabs/ssh"
)

// failSession показывает пользователю причину, по которой интерактивный шелл
// не запустился, и завершает сессию с кодом 1. PuTTY/KiTTY по умолчанию
// закрывают окно сразу после завершения сессии — без паузы сообщение просто
// не успевают прочитать, а видно лишь "ввёл пароль, окно закрылось".
func failSession(s ssh.Session, msg string) {
	_, _ = io.WriteString(s, "\r\n"+msg)
	time.Sleep(8 * time.Second)
	s.Exit(1)
}
