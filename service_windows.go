//go:build windows

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

// Значения по умолчанию — используются, если -k/-n/-d не заданы явно.
const (
	defaultRegKey   = "frpwin"      // имя ключа в реестре (services.msc: Properties > Service name)
	defaultDispName = "Frpwin"      // отображаемое имя (services.msc: колонка Name)
	defaultDesc     = "Windows frp" // описание службы
)

// regKeyOrDefault — какой именно ключ реестра/имя службы использовать:
// то, что явно передали через -k/--key, иначе "frpwin". Нужен и при
// установке, и при uninstall/start/stop — чтобы управлять КОНКРЕТНЫМ
// установленным инстансом, если их несколько (несколько -k на одном exe).
func regKeyOrDefault(k string) string {
	if k == "" {
		return defaultRegKey
	}
	return k
}

// runServiceAware разбирает аргументы командной строки и решает, как
// запускать программу:
//   - -i/--install (или старое "install")   — регистрирует Windows-службу
//   - -u/--uninstall (или старое "uninstall") — удаляет службу
//   - "start"  — запускает уже установленную службу через SCM
//   - "stop"   — останавливает службу через SCM
//   - без этих флагов, запущено вручную (двойной клик/консоль) — работает
//     как раньше, в текущем окне, до Ctrl+C
//   - без этих флагов, но запущено САМИМ Windows SCM (после "start" или
//     при автозапуске) — работает в режиме службы, отчитывается о статусе
func runServiceAware(args parsedArgs, app func()) {
	switch {
	case args.Install:
		mustPrintErr(installService(args))
		return
	case args.Uninstall:
		mustPrintErr(uninstallService(regKeyOrDefault(args.RegKey)))
		return
	case args.Start:
		mustPrintErr(startService(regKeyOrDefault(args.RegKey)))
		return
	case args.Stop:
		mustPrintErr(controlService(regKeyOrDefault(args.RegKey), svc.Stop, svc.Stopped))
		return
	}

	isService, err := svc.IsWindowsService()
	if err != nil {
		log.Printf("не смог определить режим запуска (обычный/служба): %v — запускаю как обычную программу", err)
		isService = false
	}

	if isService {
		// Ключ реестра, под которым нас должен был запустить SCM, приходит
		// как -k в args (мы всегда прописываем его в аргументы службы при
		// установке — см. installService) — так svc.Run() регистрируется
		// под тем же именем, что и сама служба, даже если их несколько на
		// одном exe.
		runAsService(app, regKeyOrDefault(args.RegKey))
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
	go s.app() // app() блокируется навсегда сам по себе — не ждём его
	changes <- svc.Status{State: svc.Running, Accepts: accepted}

	for req := range r {
		switch req.Cmd {
		case svc.Interrogate:
			changes <- req.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			// app() не поддерживает graceful shutdown (нет состояния,
			// которое было бы жалко потерять — host_key/id_rsa уже на
			// диске), поэтому просто выходим. SCM корректно считает
			// процесс остановленным по факту завершения.
			return false, 0
		}
	}
	return false, 0
}

func runAsService(app func(), regKey string) {
	elog, err := eventlog.Open(regKey)
	if err == nil {
		defer elog.Close()
		elog.Info(1, "winssh-tunnel: служба запускается")
	}
	if err := svc.Run(regKey, &winsshService{app: app}); err != nil {
		if elog != nil {
			elog.Error(1, fmt.Sprintf("winssh-tunnel: ошибка службы: %v", err))
		}
	}
}

// installService регистрирует Windows-службу, указывающую на ТЕКУЩИЙ exe
// (его расположение на диске определяется автоматически — os.Executable()).
// Конфиг, ключ реестра, имя и описание можно переопределить через
// -c/-k/-n/-d — если не заданы, используются дефолты.
func installService(args parsedArgs) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("не могу определить путь к exe: %w", err)
	}

	regKey := regKeyOrDefault(args.RegKey)
	dispName := args.Name
	if dispName == "" {
		dispName = defaultDispName
	}
	desc := args.Desc
	if desc == "" {
		desc = defaultDesc
	}

	// Конфиг по умолчанию — "frpc.toml" рядом с exe; если задан -c, берём
	// его как есть (и абсолютизируем, чтобы при запуске под SCM, у
	// которого рабочая директория по умолчанию System32, путь всё равно
	// разрешился однозначно).
	configPath := expandWinEnv(args.Config)
	if configPath == "" {
		configPath = filepath.Join(filepath.Dir(exePath), "frpc.toml")
	}
	absConfigPath, err := filepath.Abs(configPath)
	if err != nil {
		return fmt.Errorf("не могу определить абсолютный путь конфига: %w", err)
	}
	if _, err := os.Stat(absConfigPath); err != nil {
		// Не блокируем установку — конфиг могут положить чуть позже —
		// но предупреждаем сразу, а не когда служба откажется стартовать.
		fmt.Printf("Внимание: файл конфига пока не найден: %s\n", absConfigPath)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("не могу подключиться к Service Control Manager " +
			"(запусти командную строку от имени Администратора): " + err.Error())
	}
	defer m.Disconnect()

	if s, err := m.OpenService(regKey); err == nil {
		s.Close()
		return fmt.Errorf("служба с ключом %q уже установлена (сначала: winssh-tunnel.exe --uninstall -k %s)", regKey, regKey)
	}

	// -c и -k прописываем в сами аргументы запуска службы: SCM будет
	// передавать их при КАЖДОМ старте — это и есть то, как один и тот же
	// exe узнаёт при запуске под SCM, какой конфиг читать и под каким
	// именем регистрироваться в svc.Run().
	s, err := m.CreateService(regKey, exePath, mgr.Config{
		DisplayName: dispName,
		Description: desc,
		StartType:   mgr.StartAutomatic,
	}, "-c", absConfigPath, "-k", regKey)
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

	_ = eventlog.InstallAsEventCreate(regKey, eventlog.Error|eventlog.Warning|eventlog.Info)

	fmt.Printf("Служба установлена:\n")
	fmt.Printf("  Ключ реестра (Service name): %s\n", regKey)
	fmt.Printf("  Отображаемое имя:            %s\n", dispName)
	fmt.Printf("  Описание:                    %s\n", desc)
	fmt.Printf("  Конфиг:                      %s\n", absConfigPath)
	fmt.Printf("\nЗапусти прямо сейчас: winssh-tunnel.exe start")
	if args.RegKey != "" {
		fmt.Printf(" -k %s", regKey)
	}
	fmt.Println()
	return nil
}

func uninstallService(regKey string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("не могу подключиться к Service Control Manager " +
			"(запусти командную строку от имени Администратора): " + err.Error())
	}
	defer m.Disconnect()

	s, err := m.OpenService(regKey)
	if err != nil {
		return fmt.Errorf("служба с ключом %q не найдена (уже удалена?)", regKey)
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
	_ = eventlog.Remove(regKey)

	fmt.Printf("Служба (ключ %q) удалена.\n", regKey)
	return nil
}

func startService(regKey string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("не могу подключиться к Service Control Manager " +
			"(запусти командную строку от имени Администратора): " + err.Error())
	}
	defer m.Disconnect()

	s, err := m.OpenService(regKey)
	if err != nil {
		return fmt.Errorf("служба с ключом %q не установлена (сначала: winssh-tunnel.exe --install)", regKey)
	}
	defer s.Close()

	if err := s.Start(); err != nil {
		return fmt.Errorf("не могу запустить службу: %w", err)
	}
	return nil
}

func controlService(regKey string, cmd svc.Cmd, to svc.State) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("не могу подключиться к Service Control Manager " +
			"(запусти командную строку от имени Администратора): " + err.Error())
	}
	defer m.Disconnect()

	s, err := m.OpenService(regKey)
	if err != nil {
		return fmt.Errorf("служба с ключом %q не установлена", regKey)
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
