//go:build !windows

package main

import (
	"fmt"
	"os"
)

// runServiceAware на не-Windows платформах служб не бывает (в смысле
// Windows Service Control Manager) — просто запускаем приложение как есть.
// Если кто-то передаст install/uninstall/start/stop — вежливо объясняем,
// что это Windows-фича, вместо того чтобы просто их проигнорировать.
func runServiceAware(app func()) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install", "uninstall", "start", "stop":
			fmt.Println("Управление службой (install/uninstall/start/stop) — это Windows-фича.")
			fmt.Println("На этой платформе просто запусти программу напрямую.")
			return
		}
	}
	app()
}
