package main

import (
	"log"
	"runtime"

	"github.com/HumaCode/go-breeze-auth/breezeauth"
	"github.com/HumaCode/go-breeze-auth/config"
	"github.com/HumaCode/go-breeze-auth/internal/delivery/http/handler"
	"github.com/HumaCode/go-breeze-auth/internal/delivery/http/router"

	"github.com/nelthaarion/breeze/v2"
)

func main() {
	log.Println("[INFO] Starting Go Breeze Auth Service...")

	// 1. Load Configurations
	cfg := config.LoadConfig()

	// 2. Initialize Database Connection
	db, err := config.InitDB(cfg)
	if err != nil {
		log.Fatalf("[FATAL] Database initialization failed: %v", err)
	}

	// 3. Auto Migration using breezeauth package
	log.Println("[INFO] Running database migrations...")
	if err := breezeauth.AutoMigrate(db); err != nil {
		log.Fatalf("[FATAL] Auto-migration failed: %v", err)
	}
	log.Println("[INFO] Database migrations completed successfully.")

	// 4. Configure Breeze Mailer Driver
	var mailer breezeauth.Mailer
	if cfg.MailerDriver == "smtp" {
		mailer = breezeauth.NewSMTPMailer(breezeauth.SMTPConfig{
			Host:      cfg.SMTPHost,
			Port:      cfg.SMTPPort,
			Username:  cfg.SMTPUser,
			Password:  cfg.SMTPPassword,
			FromEmail: cfg.MailFromAddress,
			FromName:  cfg.MailFromName,
		})
		log.Println("[INFO] Mailer initialized with SMTP Driver")
	} else {
		mailer = breezeauth.NewLogMailer()
		log.Println("[INFO] Mailer initialized with Console Log Driver (URLs printed to terminal)")
	}

	// 5. Initialize Core BreezeAuth Service
	breezeAuthService := breezeauth.New(db, breezeauth.Config{
		JWTSecret:                cfg.JWTSecret,
		JWTExpiration:            cfg.JWTExpirationDuration(),
		FrontendResetPasswordURL: cfg.FrontendResetPasswordURL,
		FrontendVerifyEmailURL:   cfg.FrontendVerifyEmailURL,
		Mailer:                   mailer,
		RequireEmailVerification: cfg.RequireEmailVerification,
	})

	// 6. Setup Handlers & Router
	authHandler := handler.NewAuthHandler(breezeAuthService)
	appRouter := router.SetupRouter(&router.RouterDependencies{
		Config:      cfg,
		AuthHandler: authHandler,
	})

	// 7. Initialize Worker Pool & Start Breeze Server
	workerConcurrency := runtime.NumCPU() * 4
	if workerConcurrency < 8 {
		workerConcurrency = 8
	}
	pool := breeze.NewEventLoopWorkerPool(workerConcurrency)

	app := breeze.New(appRouter, pool)
	log.Printf("[INFO] Go Breeze Auth Server running on port :%d (Workers: %d)", cfg.AppPort, workerConcurrency)
	if err := app.Run(cfg.AppPort, true); err != nil {
		log.Fatalf("[FATAL] Breeze server terminated with error: %v", err)
	}
}
