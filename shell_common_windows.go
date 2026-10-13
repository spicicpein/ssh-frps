//go:build windows

package main

import (
	"io"
	"log"
	"time"
	"unsafe"

	"github.com/gliderlabs/ssh"
	"golang.org/x/sys/windows"
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

// ── Job Object: гарантированная уборка процессов сессии ─────────────────────
//
// Без этого после закрытия окна SSH-клиента (или при обрыве связи) в системе
// оставались cmd.exe и winpty-agent.exe, а в многопользовательском сценарии
// такие "зомби" копятся без ограничений. Все процессы сессии помещаются в Job
// Object с флагом KILL_ON_JOB_CLOSE: когда мы закрываем его хендл (или когда
// умирает сам winssh-tunnel.exe — Windows закрывает хендлы умершего процесса),
// система убивает ВСЕ процессы в job, включая потомков шелла (всё, что
// пользователь успел запустить из cmd.exe).

const (
	jobObjectLimitKillOnJobClose      = 0x00002000
	jobObjectExtendedLimitInformation = 9
	processTerminate                  = 0x0001
	processSetQuota                   = 0x0100
)

type jobIOCounters struct {
	ReadOperationCount, WriteOperationCount, OtherOperationCount uint64
	ReadTransferCount, WriteTransferCount, OtherTransferCount    uint64
}

type jobBasicLimitInfo struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type jobExtendedLimitInfo struct {
	BasicLimitInformation jobBasicLimitInfo
	IoInfo                jobIOCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

type killJob struct{ h windows.Handle }

// newKillJob возвращает nil, если Job Object создать не удалось (например,
// ограничения среды запуска) — все методы nil-безопасны, а явное
// TerminateProcess в обработчиках остаётся запасным вариантом.
func newKillJob() *killJob {
	h, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		log.Println("sshd: не удалось создать Job Object:", err)
		return nil
	}
	var info jobExtendedLimitInfo
	info.BasicLimitInformation.LimitFlags = jobObjectLimitKillOnJobClose
	if _, err := windows.SetInformationJobObject(h, jobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		log.Println("sshd: не удалось настроить Job Object:", err)
		windows.CloseHandle(h)
		return nil
	}
	return &killJob{h: h}
}

// add помещает процесс (по хендлу с правами SET_QUOTA|TERMINATE) в job.
func (j *killJob) add(proc windows.Handle, what string) {
	if j == nil || proc == 0 {
		return
	}
	if err := windows.AssignProcessToJobObject(j.h, proc); err != nil {
		log.Printf("sshd: не удалось поместить %s в Job Object: %v", what, err)
	}
}

// addPid — то же самое по PID (для ConPTY, где наружу отдаётся только PID).
func (j *killJob) addPid(pid uint32, what string) {
	if j == nil {
		return
	}
	ph, err := windows.OpenProcess(processSetQuota|processTerminate, false, pid)
	if err != nil {
		log.Printf("sshd: не удалось открыть %s (pid %d): %v", what, pid, err)
		return
	}
	defer windows.CloseHandle(ph)
	j.add(ph, what)
}

// kill закрывает job — система убивает все процессы в нём. Идемпотентно.
func (j *killJob) kill() {
	if j == nil || j.h == 0 {
		return
	}
	windows.CloseHandle(j.h)
	j.h = 0
}
