package config

import (
	"log"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	AppName                     string
	AppEnv                      string
	AppPort                     int
	AppURL                      string
	DBHost                      string
	DBPort                      string
	DBUser                      string
	DBPassword                  string
	DBName                      string
	DBSSLMode                   string
	JWTSecret                   string
	JWTExpirationHours          int
	MailerDriver                string // "log" or "smtp"
	SMTPHost                    string
	SMTPPort                    int
	SMTPUser                    string
	SMTPPassword                string
	MailFromAddress             string
	MailFromName                string
	FrontendResetPasswordURL    string
	FrontendVerifyEmailURL      string
	RequireEmailVerification    bool
}

var AppConfig *Config

func LoadConfig() *Config {
	if err := godotenv.Load(); err != nil {
		log.Println("[INFO] No .env file found or failed to load, reading from environment variables")
	}

	port, _ := strconv.Atoi(getEnv("APP_PORT", "8000"))
	jwtHours, _ := strconv.Atoi(getEnv("JWT_EXPIRATION_HOURS", "24"))
	smtpPort, _ := strconv.Atoi(getEnv("SMTP_PORT", "2525"))
	reqVerify, _ := strconv.ParseBool(getEnv("REQUIRE_EMAIL_VERIFICATION", "false"))

	AppConfig = &Config{
		AppName:                  getEnv("APP_NAME", "Go Breeze Auth"),
		AppEnv:                   getEnv("APP_ENV", "local"),
		AppPort:                  port,
		AppURL:                   getEnv("APP_URL", "http://localhost:8000"),
		DBHost:                   getEnv("DB_HOST", "127.0.0.1"),
		DBPort:                   getEnv("DB_PORT", "5432"),
		DBUser:                   getEnv("DB_USER", "postgres"),
		DBPassword:               getEnv("DB_PASSWORD", "postgres"),
		DBName:                   getEnv("DB_NAME", "go_breeze_auth"),
		DBSSLMode:                getEnv("DB_SSLMODE", "disable"),
		JWTSecret:                getEnv("JWT_SECRET", "super-secret-jwt-key-change-this-in-production"),
		JWTExpirationHours:       jwtHours,
		MailerDriver:             getEnv("MAILER_DRIVER", "log"),
		SMTPHost:                 getEnv("SMTP_HOST", "smtp.mailtrap.io"),
		SMTPPort:                 smtpPort,
		SMTPUser:                 getEnv("SMTP_USER", ""),
		SMTPPassword:             getEnv("SMTP_PASSWORD", ""),
		MailFromAddress:          getEnv("MAIL_FROM_ADDRESS", "hello@example.com"),
		MailFromName:             getEnv("MAIL_FROM_NAME", "Go Breeze Auth"),
		FrontendResetPasswordURL: getEnv("FRONTEND_RESET_PASSWORD_URL", "http://localhost:3000/reset-password"),
		FrontendVerifyEmailURL:   getEnv("FRONTEND_VERIFY_EMAIL_URL", "http://localhost:3000/verify-email"),
		RequireEmailVerification: reqVerify,
	}

	return AppConfig
}

func (c *Config) JWTExpirationDuration() time.Duration {
	if c.JWTExpirationHours <= 0 {
		return 24 * time.Hour
	}
	return time.Duration(c.JWTExpirationHours) * time.Hour
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

