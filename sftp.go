package main

import (
	"log"

	"github.com/gliderlabs/ssh"
	"github.com/pkg/sftp"
)

// sftpHandler отдаёт файловую систему по SFTP поверх той же ssh-сессии.
// pkg/sftp сам транслирует запросы в обычные os.Open/os.Stat/os.Mkdir и т.д.,
// поэтому работает на Windows так же, как и везде — без ConPTY и прочего,
// в отличие от интерактивного шелла. Прав доступа никаких отдельно не
// ограничиваем: раз человек прошёл пароль sshd, у него те же права на
// файлы, что и у пользователя, от имени которого запущен winssh-tunnel.exe.
func sftpHandler(s ssh.Session) {
	srv, err := sftp.NewServer(s)
	if err != nil {
		log.Println("sftp: не удалось создать сервер:", err)
		return
	}
	defer srv.Close()

	if err := srv.Serve(); err != nil {
		log.Println("sftp: сессия завершилась:", err)
	}
}
