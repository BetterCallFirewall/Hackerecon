package main

import (
	"log"

	"github.com/BetterCallFirewall/Hackerecon/internal/config"
	"github.com/BetterCallFirewall/Hackerecon/internal/driven"
)

func main() {
	err := NewSecurityProxyWithGenkit("", "", "", "")
	fmt.Println(err)

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Инициализируем менеджер для работы с сертификатами
	certManager, err := cert.NewCertManager(cfg)
	if err != nil {
		log.Fatalf("Failed to create cert manager: %v", err)
	}

	// Запускаем прокси сервер
	proxyServer := proxy.NewServer(cfg, store, certManager)
	go func() {
		log.Printf("Starting proxy server on %s", cfg.Proxy.ListenAddr)
		if err := proxyServer.Start(); err != nil {
			log.Fatalf("Proxy server failed: %v", err)
		}
	}()

	// Запускаем веб-интерфейс
	webServer := web.NewServer(cfg, store)
	go func() {
		log.Printf("Starting web interface on %s", cfg.Web.ListenAddr)
		if err := webServer.Start(); err != nil {
			log.Fatalf("Web server failed: %v", err)
		}
	}()

	// Graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	log.Println("Shutting down...")
	proxyServer.Stop()
	webServer.Stop()
}

// NewSecurityProxyWithGenkit создает новый прокси с Genkit интеграцией
func NewSecurityProxyWithGenkit(port, burpHost, burpPort, geminiAPIKey string) error {
	ctx := context.Background()

	fmt.Println("START")
	// Инициализируем Genkit с плагинами
	genkitApp := genkit.Init(
		ctx,
		genkit.WithPlugins(
			&googlegenai.GoogleAI{
				APIKey: geminiAPIKey,
			},
		),
		genkit.WithDefaultModel("googleai/gemini-2.5-flash"),
	)
	fmt.Println(genkitApp)

	return nil
}
