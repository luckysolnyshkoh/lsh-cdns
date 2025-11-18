package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// Глобальные переменные
var DEBUG int = 1     // 0=нет дебага, 1=экран, 2=логфайл, 3=экран+логфайл
var BinaryPath string // Директория с бинарником (без имени файла)
var BinaryName string // Имя бинарника без пути
var DNS_COUNT int
var DnsServers []string
var BIND_IP string                // IP для привязки DNS сервера
var dnsMappings map[string]string // Маппинг FQDN -> Resolver IP
var tldMappings []TldMapping      // Список TLD маппингов с приоритетами

// TldMapping представляет маппинг TLD домена к резолверу
type TldMapping struct {
	Domain   string // домен (например, "ru", "ya.ru")
	Resolver string // резолвер IP
}

func main() {
	// Определяем путь к бинарнику и разделяем на директорию и имя
	var err error
	fullBinaryPath, err := filepath.Abs(os.Args[0])
	if err != nil {
		fmt.Printf("Ошибка определения пути к бинарнику: %v\n", err)
		return
	}

	// Разделяем полный путь на директорию и имя файла
	BinaryPath = filepath.Dir(fullBinaryPath)
	BinaryName = filepath.Base(fullBinaryPath)

	// Создаем необходимые директории
	createDirectories()

	// Сначала читаем только DEBUG из env файла
	err = readDebugFromEnvFile("./etc/main.env")
	if err != nil {
		fmt.Printf("Ошибка чтения DEBUG из env файла: %v\n", err)
		return
	}

	// Устанавливаем уровень DEBUG
	setDebugLevel()
	debugLog("INFO", fmt.Sprintf("Уровень DEBUG: %d", DEBUG))

	// Теперь читаем все переменные окружения из файла
	err = readEnvFile("./etc/main.env")
	if err != nil {
		debugLog("ERROR", fmt.Sprintf("Ошибка чтения env файла: %v", err))
		return
	}

	// Читаем переменную DNS_COUNT и логируем ее
	DNS_COUNT, _ = strconv.Atoi(os.Getenv("DNS_COUNT"))
	debugLog("INFO", fmt.Sprintf("DNS_COUNT: %d", DNS_COUNT))

	// Читаем BIND_IP
	BIND_IP = os.Getenv("BIND_IP")
	if BIND_IP == "" {
		BIND_IP = "127.0.0.1" // По умолчанию
		debugLog("WARNING", "BIND_IP не установлен, используем 127.0.0.1")
	}
	debugLog("INFO", fmt.Sprintf("BIND_IP: %s", BIND_IP))

	// Загружаем маппинги из конфигурационных файлов
	err = loadDnsMappings()
	if err != nil {
		debugLog("ERROR", fmt.Sprintf("Ошибка загрузки DNS маппингов: %v", err))
		return
	}

	// Загружаем TLD маппинги
	err = loadTldMappings()
	if err != nil {
		debugLog("ERROR", fmt.Sprintf("Ошибка загрузки TLD маппингов: %v", err))
		return
	}

	// Проверяем содержимое TLD маппингов
	debugLog("DEBUG", fmt.Sprintf("Всего TLD маппингов загружено: %d", len(tldMappings)))
	for i, mapping := range tldMappings {
		debugLog("DEBUG", fmt.Sprintf("TLD маппинг %d: '%s' -> '%s'", i+1, mapping.Domain, mapping.Resolver))
	}

	// Обрабатываем DNS серверы
	processDnsServers()

	// Запускаем DNS сервер
	debugLog("INFO", "Запуск DNS прокси сервера...")
	startDnsServer()

	debugLog("INFO", "Программа завершена успешно")
}

// loadTldMappings загружает TLD маппинги из файла main-domains.cfg
func loadTldMappings() error {
	file, err := os.Open("./etc/main-domains.cfg")
	if err != nil {
		return fmt.Errorf("не удалось открыть файл ./etc/main-domains.cfg: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())

		// Пропускаем пустые строки и комментарии
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Разделяем строку на домен и резолвер
		parts := strings.Fields(line)
		if len(parts) != 2 {
			debugLog("WARNING", fmt.Sprintf("Строка %d в main-domains.cfg не содержит два поля: %s", lineNumber, line))
			continue
		}

		domain := normalizeFQDN(strings.TrimSpace(parts[0]))
		resolver := strings.TrimSpace(parts[1])

		// Проверяем валидность IP адреса
		if !isValidIP(resolver) {
			debugLog("WARNING", fmt.Sprintf("Некорректный IP адрес в строке %d: %s", lineNumber, resolver))
			continue
		}

		tldMappings = append(tldMappings, TldMapping{
			Domain:   domain,
			Resolver: resolver,
		})

		debugLog("DEBUG", fmt.Sprintf("Загружен TLD маппинг #%d: %s -> %s", len(tldMappings), domain, resolver))
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("ошибка чтения файла main-domains.cfg: %v", err)
	}

	// Сортируем по длине домена (более длинные домены first для приоритета)
	tldMappings = sortTldMappings(tldMappings)

	debugLog("INFO", fmt.Sprintf("Загружено %d TLD маппингов", len(tldMappings)))

	// Выводим отсортированный список для отладки
	for i, mapping := range tldMappings {
		debugLog("DEBUG", fmt.Sprintf("TLD маппинг #%d (приоритет %d): %s -> %s", i+1, len(tldMappings)-i, mapping.Domain, mapping.Resolver))
	}

	return nil
}

// sortTldMappings сортирует TLD маппинги по длине домена (desc) для приоритета
func sortTldMappings(mappings []TldMapping) []TldMapping {
	// Простая сортировка пузырьком по длине домена (более длинные first)
	for i := 0; i < len(mappings); i++ {
		for j := i + 1; j < len(mappings); j++ {
			if len(mappings[i].Domain) < len(mappings[j].Domain) {
				mappings[i], mappings[j] = mappings[j], mappings[i]
			}
		}
	}
	return mappings
}

// findTldResolver находит резолвер для TLD домена
func findTldResolver(fqdn string) (string, bool) {
	debugLog("DEBUG", fmt.Sprintf("Ищем TLD резолвер для: %s", fqdn))

	// Проверяем все TLD маппинги (уже отсортированы по приоритету)
	for i, mapping := range tldMappings {
		// Проверяем точное совпадение или суффикс
		if fqdn == mapping.Domain || strings.HasSuffix(fqdn, "."+mapping.Domain) {
			debugLog("DEBUG", fmt.Sprintf("Найден TLD маппинг #%d для %s: %s -> %s", i+1, fqdn, mapping.Domain, mapping.Resolver))
			return mapping.Resolver, true
		}
	}

	debugLog("DEBUG", fmt.Sprintf("TLD резолвер для %s не найден", fqdn))
	return "", false
}

// startDnsServer запускает DNS прокси сервер
func startDnsServer() {
	// Создаем DNS сервер
	dns.HandleFunc(".", dnsHandler)
	server := &dns.Server{
		Addr:    fmt.Sprintf("%s:53", BIND_IP),
		Net:     "udp",
		Handler: dns.HandlerFunc(dnsHandler),
	}

	debugLog("INFO", fmt.Sprintf("DNS сервер запущен на %s:53", BIND_IP))

	// Запускаем сервер
	err := server.ListenAndServe()
	if err != nil {
		debugLog("ERROR", fmt.Sprintf("Ошибка запуска DNS сервера: %v", err))
		return
	}
}

// dnsHandler обрабатывает DNS запросы
func dnsHandler(w dns.ResponseWriter, r *dns.Msg) {
	clientIP := w.RemoteAddr().String()

	// Проверяем первый вопрос в запросе
	if len(r.Question) == 0 {
		debugLog("WARNING", "Получен пустой DNS запрос")
		w.WriteMsg(r)
		return
	}

	question := r.Question[0]
	fqdn := normalizeFQDN(question.Name) // Нормализуем FQDN

	debugLog("DEBUG", fmt.Sprintf("Получен DNS запрос от %s: %s", clientIP, fqdn))

	// Создаем ответ
	m := new(dns.Msg)
	m.SetReply(r)

	// Этап 1: Проверяем кастомные маппинги
	if resolver, found := dnsMappings[fqdn]; found {
		debugLog("INFO", fmt.Sprintf("FQDN %s найден в кастомном маппинге, резолвим через %s", fqdn, resolver))
		if resolveThroughCustomResolverWithCheck(w, m, question, resolver) {
			return // Успешно резолвили
		}
		// Если кастомный резолвер вернул NXDOMAIN, продолжаем к TLD
		debugLog("DEBUG", fmt.Sprintf("Кастомный резолвер для %s вернул NXDOMAIN, пробуем TLD", fqdn))
	}

	// Этап 2: Проверяем TLD маппинги
	if resolver, found := findTldResolver(fqdn); found {
		debugLog("INFO", fmt.Sprintf("FQDN %s найден в TLD маппинге, резолвим через %s", fqdn, resolver))
		if resolveThroughCustomResolverWithCheck(w, m, question, resolver) {
			return // Успешно резолвили
		}
		// Если TLD резолвер вернул NXDOMAIN, продолжаем к стандартным DNS
		debugLog("DEBUG", fmt.Sprintf("TLD резолвер для %s вернул NXDOMAIN, пробуем стандартные DNS", fqdn))
	} else {
		debugLog("DEBUG", fmt.Sprintf("FQDN %s не найден в TLD маппингах, используем стандартные DNS", fqdn))
	}

	// Этап 3: Если нет кастомного/TLD маппинга или они вернули NXDOMAIN, используем стандартные DNS серверы
	if len(DnsServers) > 0 {
		resolveThroughStandardResolvers(w, m, question)
	} else {
		debugLog("WARNING", "Нет доступных DNS серверов")
		w.WriteMsg(m)
	}
}

// resolveThroughCustomResolverWithCheck резолвит через кастомный резолвер и проверяет результат
func resolveThroughCustomResolverWithCheck(w dns.ResponseWriter, m *dns.Msg, question dns.Question, resolver string) bool {
	client := new(dns.Client)
	client.Net = "udp"

	// Создаем запрос для резолвера
	req := new(dns.Msg)
	req.SetQuestion(question.Name, question.Qtype)

	// Отправляем запрос к резолверу
	resp, _, err := client.Exchange(req, fmt.Sprintf("%s:53", resolver))
	if err != nil {
		debugLog("ERROR", fmt.Sprintf("Ошибка резолвинга через %s: %v", resolver, err))
		return false
	}

	// Если это NXDOMAIN, считаем ошибкой
	if resp.Rcode == dns.RcodeNameError {
		debugLog("DEBUG", fmt.Sprintf("Резолвер %s вернул NXDOMAIN для %s", resolver, question.Name))
		return false
	}

	// Для всех остальных кодов ответа копируем ответ как есть
	m.Answer = resp.Answer
	m.Ns = resp.Ns
	m.Extra = resp.Extra
	m.Rcode = resp.Rcode

	debugLog("INFO", fmt.Sprintf("Резолвер %s вернул код %d, записей: %d для %s",
		resolver, resp.Rcode, len(m.Answer), question.Name))

	w.WriteMsg(m)
	return true // Считаем любой ответ кроме NXDOMAIN успешным
}

// resolveThroughStandardResolvers резолвит через стандартные DNS серверы
func resolveThroughStandardResolvers(w dns.ResponseWriter, m *dns.Msg, question dns.Question) {
	client := new(dns.Client)
	client.Net = "udp"

	for i, resolver := range DnsServers {
		debugLog("DEBUG", fmt.Sprintf("Пробуем резолвить через DNS сервер %d: %s", i+1, resolver))

		// Создаем запрос для резолвера
		req := new(dns.Msg)
		req.SetQuestion(question.Name, question.Qtype)

		// Отправляем запрос к резолверу
		resp, _, err := client.Exchange(req, fmt.Sprintf("%s:53", resolver))
		if err != nil {
			debugLog("WARNING", fmt.Sprintf("Ошибка резолвинга через %s: %v", resolver, err))
			continue
		}

		// Если получили ответ, возвращаем его
		if resp != nil && len(resp.Answer) > 0 {
			m.Answer = resp.Answer
			m.Ns = resp.Ns
			m.Extra = resp.Extra
			m.Rcode = resp.Rcode

			debugLog("INFO", fmt.Sprintf("Успешно резолвлен %s через %s", question.Name, resolver))
			w.WriteMsg(m)
			return
		}
	}

	debugLog("WARNING", fmt.Sprintf("Не удалось резолвить %s через все доступные DNS серверы", question.Name))
	w.WriteMsg(m)
}

// normalizeFQDN нормализует FQDN - убирает точку в конце и приводит к нижнему регистру
func normalizeFQDN(fqdn string) string {
	// Убираем точку в конце если есть
	fqdn = strings.TrimSuffix(fqdn, ".")
	// Приводим к нижнему регистру для корректного сравнения
	return strings.ToLower(fqdn)
}

// loadDnsMappings загружает маппинги из файла main.cfg
func loadDnsMappings() error {
	dnsMappings = make(map[string]string)

	file, err := os.Open("./etc/main.cfg")
	if err != nil {
		return fmt.Errorf("не удалось открыть файл ./etc/main.cfg: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())

		// Пропускаем пустые строки и комментарии
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Разделяем строку на FQDN и Resolver IP
		parts := strings.Fields(line)
		if len(parts) != 2 {
			debugLog("WARNING", fmt.Sprintf("Строка %d в main.cfg не содержит два поля: %s", lineNumber, line))
			continue
		}

		fqdn := normalizeFQDN(strings.TrimSpace(parts[0])) // Нормализуем FQDN
		resolver := strings.TrimSpace(parts[1])

		// Проверяем валидность IP адреса
		if !isValidIP(resolver) {
			debugLog("WARNING", fmt.Sprintf("Некорректный IP адрес в строке %d: %s", lineNumber, resolver))
			continue
		}

		dnsMappings[fqdn] = resolver
		debugLog("DEBUG", fmt.Sprintf("Загружен маппинг: %s -> %s", fqdn, resolver))
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("ошибка чтения файла main.cfg: %v", err)
	}

	debugLog("INFO", fmt.Sprintf("Загружено %d DNS маппингов", len(dnsMappings)))
	return nil
}

// isValidIP проверяет валидность IP адреса
func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// processDnsServers обрабатывает список DNS серверов
func processDnsServers() {
	DnsServers = []string{}
	for i := 1; i <= DNS_COUNT; i++ {
		envVarName := fmt.Sprintf("DNS%d", i)
		if dnsServer := os.Getenv(envVarName); dnsServer != "" {
			DnsServers = append(DnsServers, dnsServer)
		}
	}

	// Цикл по слайсу DNS серверов
	debugLog("INFO", fmt.Sprintf("Загружено %d DNS серверов", len(DnsServers)))
	for i, dnsServer := range DnsServers {
		debugLog("INFO", fmt.Sprintf("DNS сервер %d: %s", i+1, dnsServer))
	}
}

// readDebugFromEnvFile читает только переменную DEBUG из файла
func readDebugFromEnvFile(filepath string) error {
	file, err := os.Open(filepath)
	if err != nil {
		return fmt.Errorf("не удалось открыть файл %s: %v", filepath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Пропускаем пустые строки и комментарии
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Ищем знак "="
		equalIndex := strings.Index(line, "=")
		if equalIndex == -1 {
			continue
		}

		// Извлекаем ключ и значение
		key := strings.TrimSpace(line[:equalIndex])
		value := strings.TrimSpace(line[equalIndex+1:])

		// Убираем кавычки если есть
		value = strings.Trim(value, `"'`)

		// Если это переменная DEBUG, устанавливаем ее
		if key == "DEBUG" {
			if debugInt, err := strconv.Atoi(value); err == nil {
				DEBUG = debugInt
			} else {
				fmt.Printf("WARNING: Некорректное значение DEBUG в env файле: %s, используем 0\n", value)
				DEBUG = 0
			}
			return nil // Нашли DEBUG, можно выходить
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("ошибка чтения файла %s: %v", filepath, err)
	}

	// Если DEBUG не найден, оставляем 0
	return nil
}

// setDebugLevel устанавливает уровень DEBUG (если уже установлен, не меняет)
func setDebugLevel() {
	// DEBUG уже установлен в readDebugFromEnvFile, здесь можно добавить дополнительную логику если нужно
}

// debugLog - основная функция для логирования в зависимости от уровня DEBUG
func debugLog(level, message string) {
	// Если дебаг отключен, ничего не выводим
	if DEBUG == 0 {
		return
	}

	// Формируем сообщение
	logMessage := fmt.Sprintf("[%s] %s", level, message)

	// Выводим на экран если DEBUG >= 1
	if DEBUG >= 1 {
		fmt.Println(logMessage)
	}

	// Записываем в файл если DEBUG >= 2
	if DEBUG >= 2 {
		err := writeToLogFile(logMessage)
		if err != nil {
			// Если не удалось записать в файл, выводим на экран
			fmt.Printf("КРИТИЧЕСКАЯ ОШИБКА: Не удалось записать в логфайл: %v\n", err)
		}
	}
}

// readEnvFile читает переменные окружения из файла
func readEnvFile(filepath string) error {
	file, err := os.Open(filepath)
	if err != nil {
		return fmt.Errorf("не удалось открыть файл %s: %v", filepath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())

		// Пропускаем пустые строки и комментарии
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Ищем знак "="
		equalIndex := strings.Index(line, "=")
		if equalIndex == -1 {
			debugLog("WARNING", fmt.Sprintf("Строка %d в файле %s не содержит знак '='", lineNumber, filepath))
			continue
		}

		// Извлекаем ключ и значение
		key := strings.TrimSpace(line[:equalIndex])
		value := strings.TrimSpace(line[equalIndex+1:])

		// Убираем кавычки если есть
		value = strings.Trim(value, `"'`)

		// Устанавливаем переменную окружения
		err := os.Setenv(key, value)
		if err != nil {
			debugLog("ERROR", fmt.Sprintf("Не удалось установить переменную %s: %v", key, err))
		} else {
			debugLog("DEBUG", fmt.Sprintf("Установлена переменная %s=%s", key, value))
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("ошибка чтения файла %s: %v", filepath, err)
	}

	debugLog("DEBUG", fmt.Sprintf("Успешно прочитан файл %s", filepath))
	return nil
}

// createDirectories создает необходимые директории
func createDirectories() {
	dirs := []string{"./etc", "./logs"}

	for _, dir := range dirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			err := os.MkdirAll(dir, 0755)
			if err != nil {
				fmt.Printf("ERROR: Не удалось создать директорию %s: %v\n", dir, err)
				return
			}
			fmt.Printf("INFO: Создана директория: %s\n", dir)
		}
	}

	// Очищаем логфайл при запуске
	err := clearLogFile()
	if err != nil {
		fmt.Printf("WARNING: Не удалось очистить логфайл: %v\n", err)
	}
}

// clearLogFile очищает логфайл
func clearLogFile() error {
	// Создаем пустой файл или очищаем существующий
	file, err := os.OpenFile("./logs/main.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("не удалось очистить логфайл: %v", err)
	}
	defer file.Close()
	return nil
}

// writeToLogFile записывает сообщение в логфайл
func writeToLogFile(message string) error {
	logFile, err := os.OpenFile("./logs/main.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("не удалось открыть логфайл: %v", err)
	}
	defer logFile.Close()

	_, err = logFile.WriteString(message + "\n")
	return err
}
