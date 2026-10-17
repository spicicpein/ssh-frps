package main

import (
	"io"
	"log"
	"os"

	"github.com/gliderlabs/ssh"
	"github.com/pkg/sftp"
)

// newSFTPServer создаёт SFTP-сервер поверх rwc. Если задан shellDir, он же
// становится "домашней" папкой SFTP (ответ на realpath ".", база для
// относительных путей) — так же, как стартовая папка интерактивного шелла.
// Без этого SFTP начинал в рабочей папке процесса, то есть там, где лежит
// frpc.toml/host_key (после chdir в main()).
func newSFTPServer(rwc io.ReadWriteCloser) (*sftp.Server, error) {
	var opts []sftp.ServerOption
	if shellStartDir != "" {
		if st, err := os.Stat(shellStartDir); err == nil && st.IsDir() {
			opts = append(opts, sftp.WithServerWorkingDirectory(shellStartDir))
		} else {
			log.Printf("sftp: shellDir %q недоступна (%v) — стартую в папке программы", shellStartDir, err)
		}
	}
	return sftp.NewServer(rwc, opts...)
}

// sftpHandler отдаёт файловую систему по SFTP поверх той же ssh-сессии.
// pkg/sftp сам транслирует запросы в обычные os.Open/os.Stat/os.Mkdir и т.д.,
// поэтому работает на Windows так же, как и везде — без ConPTY и прочего,
// в отличие от интерактивного шелла. Прав доступа никаких отдельно не
// ограничиваем: раз человек прошёл пароль sshd, у него те же права на
// файлы, что и у пользователя, от имени которого запущен winssh-tunnel.exe.
func sftpHandler(s ssh.Session) {
	srv, err := newSFTPServer(s)
	if err != nil {
		log.Println("sftp: не удалось создать сервер:", err)
		return
	}
	defer srv.Close()

	if err := srv.Serve(); err != nil && err != io.EOF {
		log.Println("sftp: сессия завершилась:", err)
	}
}
