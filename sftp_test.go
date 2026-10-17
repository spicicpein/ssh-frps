package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/pkg/sftp"
)

type pipeRWC struct {
	io.Reader
	io.Writer
	closers []io.Closer
}

func (p pipeRWC) Close() error {
	for _, c := range p.closers {
		c.Close()
	}
	return nil
}

func startTestSFTP(t *testing.T) *sftp.Client {
	t.Helper()
	c2sR, c2sW := io.Pipe()
	s2cR, s2cW := io.Pipe()
	srv, err := newSFTPServer(pipeRWC{c2sR, s2cW, []io.Closer{c2sR, s2cW}})
	if err != nil {
		t.Fatalf("newSFTPServer: %v", err)
	}
	go srv.Serve()
	client, err := sftp.NewClientPipe(s2cR, c2sW)
	if err != nil {
		t.Fatalf("NewClientPipe: %v", err)
	}
	// Сначала сервер: закрыв свои концы pipe, он даёт клиенту EOF; иначе
	// client.Close() ждёт приёмную горутину вечно.
	t.Cleanup(func() { srv.Close(); client.Close() })
	return client
}

// SFTP должен стартовать в shellDir (а не в папке, откуда запущена программа).
func TestSFTPStartsInShellDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := shellStartDir
	shellStartDir = dir
	defer func() { shellStartDir = old }()

	client := startTestSFTP(t)
	wd, err := client.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if wd != filepath.ToSlash(dir) {
		t.Fatalf("домашняя папка SFTP = %q, ожидалась %q", wd, filepath.ToSlash(dir))
	}
	infos, err := client.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	found := false
	for _, fi := range infos {
		if fi.Name() == "hello.txt" {
			found = true
		}
	}
	if !found {
		t.Fatalf("hello.txt не найден в стартовой папке SFTP, список: %v", infos)
	}
}

// Несуществующая shellDir не должна ломать SFTP — стартуем как раньше.
func TestSFTPFallsBackWhenShellDirMissing(t *testing.T) {
	old := shellStartDir
	shellStartDir = filepath.Join(t.TempDir(), "нет-такой-папки")
	defer func() { shellStartDir = old }()

	client := startTestSFTP(t)
	if _, err := client.Getwd(); err != nil {
		t.Fatalf("Getwd при недоступной shellDir: %v", err)
	}
}
