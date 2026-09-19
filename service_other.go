//go:build !windows

package main

import (
	"fmt"
)

// runServiceAware на не-Windows платформах служб не бывает (в смысле
// Windows Service Control Manager) — просто запускаем приложение как есть.
// Если кто-то передаст install/uninstall/start/stop — вежливо объясняем,
// что это Windows-фича, вместо того чтобы просто их проигнорировать.
func runServiceAware(args parsedArgs, app func()) {
	if args.Install || args.Uninstall || args.Start || args.Stop {
		fmt.Println("Управление службой (install/uninstall/start/stop) — это Windows-фича.")
		fmt.Println("На этой платформе просто запусти программу напрямую.")
		return
	}
	app()
}
