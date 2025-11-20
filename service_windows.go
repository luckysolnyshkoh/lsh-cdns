//go:build windows
// +build windows

package main

import (
    "log"
    "os"

    "golang.org/x/sys/windows/svc"
)

// Windows Service для Windows
type windowsService struct{}

func (m *windowsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
    const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
    changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

    // Инициализируем приложение для сервиса
    initializeService()

    for {
	select {
	case c := <-r:
	    switch c.Cmd {
	    case svc.Interrogate:
		changes <- c.CurrentStatus
	    case svc.Stop, svc.Shutdown:
		// Корректно останавливаем сервер
		gracefulShutdown()
		return false, 0
	    default:
		changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	    }
	}
    }
}

// initializeService инициализирует приложение для работы как служба
func initializeService() {
    log.Printf("[SERVICE] Инициализация службы...")

    // Определяем ОС
    OperatingSystem = detectOS()

    // Настраиваем пути
    setupPaths()

    log.Printf("[SERVICE] ОС: %s", OperatingSystem)
    log.Printf("[SERVICE] Путь к бинарнику: %s", BinaryPath)
    log.Printf("[SERVICE] Путь к конфигурации: %s", configPath)
    log.Printf("[SERVICE] Путь к логам: %s", logsPath)

    // Создаем необходимые директории
    createDirectories()

    // Читаем конфигурацию
    loadConfiguration()

    // Запускаем DNS сервер
    log.Printf("[SERVICE] Запуск DNS прокси сервера...")

    // Запускаем сервер в горутине, чтобы служба не блокировалась
    go func() {
	startDnsServer()
    }()

    log.Printf("[SERVICE] Служба успешно инициализирована")
}

// runWindowsService запускает Windows Service
func runWindowsService() {
    err := svc.Run("LSHCDNS", &windowsService{})
    if err != nil {
	log.Printf("Ошибка запуска службы: %v", err)
	os.Exit(1)
    }
}
