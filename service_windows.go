//go:build windows

package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

// Имя службы в реестре Windows и то, что видно в services.msc.
const (
	svcName        = "WinsshTunnel"
	svcDisplayName = "winssh-tunnel (SSH + FRP)"
	svcDescription = "Встроенный SSH-сервер с FRP-туннелем наружу. " +
		"Управление: winssh-tunnel.exe install|uninstall|start|stop"
)

// runServiceAware разбирает аргументы командной строки и решает, как
// запускать программу:
//   - "install"   — регистрирует Windows-службу (автозапуск при загрузке ОС)
//   - "uninstall" — удаляет службу
//   - "start"     — запускает уже установленную службу через SCM
//   - "stop"      — останавливает службу через SCM
//   - без аргументов, запущено вручную (двойной клик/консоль) — работает
//     как раньше, в текущем окне, до Ctrl+C
//   - без аргументов, но запущено САМИМ Windows SCM (после "start" или
//     при автозапуске) — работает в режиме службы, отчитывается о статусе
func runServiceAware(app func()) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			mustPrintErr(installService())
			return
		case "uninstall":
			mustPrintErr(uninstallService())
			return
		case "start":
			mustPrintErr(startService())
			return
		case "stop":
			mustPrintErr(controlService(svc.Stop, svc.Stopped))
			return
		}
	}

	isService, err := svc.IsWindowsService()
	if err != nil {
		log.Printf("не смог определить режим запуска (обычный/служба): %v — запускаю как обычную программу", err)
		isService = false
	}

	if isService {
		runAsService(app)
		return
	}

	// Обычный запуск (двойной клик, консоль, планировщик задач) — старое
	// поведение, без изменений.
	app()
}

func mustPrintErr(err error) {
	if err != nil {
		fmt.Println("Ошибка:", err)
		os.Exit(1)
	}
	fmt.Println("Готово.")
}

// winsshService реализует интерфейс svc.Handler — то, что дёргает сам
// Windows SCM (Service Control Manager).
type winsshService struct {
	app func()
}

func (s *winsshService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown

	changes <- svc.Status{State: svc.StartPending}
	go s.app() // runApp() блокируется навсегда сам по себе — не ждём его
	changes <- svc.Status{State: svc.Running, Accepts: accepted}

	for req := range r {
		switch req.Cmd {
		case svc.Interrogate:
			changes <- req.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			// runApp() не поддерживает graceful shutdown (нет состояния,
			// которое было бы жалко потерять — host_key/id_rsa уже на
			// диске), поэтому просто выходим. SCM корректно считает
			// процесс остановленным по факту завершения.
			return false, 0
		}
	}
	return false, 0
}

func runAsService(app func()) {
	elog, err := eventlog.Open(svcName)
	if err == nil {
		defer elog.Close()
		elog.Info(1, "winssh-tunnel: служба запускается")
	}
	if err := svc.Run(svcName, &winsshService{app: app}); err != nil {
		if elog != nil {
			elog.Error(1, fmt.Sprintf("winssh-tunnel: ошибка службы: %v", err))
		}
	}
}

func installService() error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("не могу определить путь к exe: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("не могу подключиться к Service Control Manager " +
			"(запусти командную строку от имени Администратора): " + err.Error())
	}
	defer m.Disconnect()

	if s, err := m.OpenService(svcName); err == nil {
		s.Close()
		return fmt.Errorf("служба %q уже установлена (сначала: winssh-tunnel.exe uninstall)", svcName)
	}

	s, err := m.CreateService(svcName, exePath, mgr.Config{
		DisplayName: svcDisplayName,
		Description: svcDescription,
		StartType:   mgr.StartAutomatic,
	})
	if err != nil {
		return fmt.Errorf("не могу создать службу: %w", err)
	}
	defer s.Close()

	// Автоперезапуск при падении — на случай временных сетевых сбоев.
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}, 86400) // сбросить счётчик через сутки без падений

	_ = eventlog.InstallAsEventCreate(svcName, eventlog.Error|eventlog.Warning|eventlog.Info)

	fmt.Printf("Служба %q установлена (автозапуск при загрузке Windows).\n", svcDisplayName)
	fmt.Println("Запусти прямо сейчас: winssh-tunnel.exe start")
	return nil
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("не могу подключиться к Service Control Manager " +
			"(запусти командную строку от имени Администратора): " + err.Error())
	}
	defer m.Disconnect()

	s, err := m.OpenService(svcName)
	if err != nil {
		return fmt.Errorf("служба %q не найдена (уже удалена?)", svcName)
	}
	defer s.Close()

	// Если служба ещё запущена — сначала останавливаем, иначе Delete()
	// пометит её "на удаление", но реально она пропадёт только после
	// перезагрузки.
	if status, err := s.Query(); err == nil && status.State != svc.Stopped {
		_, _ = s.Control(svc.Stop)
		for i := 0; i < 20; i++ {
			time.Sleep(500 * time.Millisecond)
			status, err = s.Query()
			if err != nil || status.State == svc.Stopped {
				break
			}
		}
	}

	if err := s.Delete(); err != nil {
		return fmt.Errorf("не могу удалить службу: %w", err)
	}
	_ = eventlog.Remove(svcName)

	fmt.Printf("Служба %q удалена.\n", svcDisplayName)
	return nil
}

func startService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("не могу подключиться к Service Control Manager " +
			"(запусти командную строку от имени Администратора): " + err.Error())
	}
	defer m.Disconnect()

	s, err := m.OpenService(svcName)
	if err != nil {
		return fmt.Errorf("служба %q не установлена (сначала: winssh-tunnel.exe install)", svcName)
	}
	defer s.Close()

	if err := s.Start(); err != nil {
		return fmt.Errorf("не могу запустить службу: %w", err)
	}
	return nil
}

func controlService(cmd svc.Cmd, to svc.State) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("не могу подключиться к Service Control Manager " +
			"(запусти командную строку от имени Администратора): " + err.Error())
	}
	defer m.Disconnect()

	s, err := m.OpenService(svcName)
	if err != nil {
		return fmt.Errorf("служба %q не установлена", svcName)
	}
	defer s.Close()

	status, err := s.Control(cmd)
	if err != nil {
		return fmt.Errorf("не могу отправить команду службе: %w", err)
	}

	for i := 0; i < 20 && status.State != to; i++ {
		time.Sleep(500 * time.Millisecond)
		status, err = s.Query()
		if err != nil {
			return fmt.Errorf("не могу проверить статус службы: %w", err)
		}
	}
	if status.State != to {
		return fmt.Errorf("служба не перешла в нужное состояние вовремя (сейчас: %d)", status.State)
	}
	return nil
}
