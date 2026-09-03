package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/gliderlabs/ssh"
)

func generateEd25519PEMKey(path string) error {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, block)
}

func ensureHostKey(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	log.Printf("Generating host key: %s", path)
	return generateEd25519PEMKey(path)
}

func handleSession(s ssh.Session) {
	io.WriteString(s, "winssh-tunnel SSH Server\r\n")
	io.WriteString(s, "Command received: ")
	io.WriteString(s, s.RawCommand())
	io.WriteString(s, "\r\n")
	s.Exit(0)
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Prepare host key
	hostKeyPath := "host_key"
	if err := ensureHostKey(hostKeyPath); err != nil {
		log.Fatalf("Failed to ensure host key: %v", err)
	}

	// Create SSH server
	server := ssh.Server{
		Addr:        ":2222",
		Handler:     handleSession,
		HostKeyFile: hostKeyPath,
	}

	log.Printf("SSH Server listening on %s", server.Addr)
	log.Printf("Test with: ssh -p 2222 user@localhost")

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start server in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.ListenAndServe()
	}()

	// Wait for signal or error
	select {
	case <-sigChan:
		log.Println("Shutting down...")
		server.Close()
	case err := <-errChan:
		if err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}
}
