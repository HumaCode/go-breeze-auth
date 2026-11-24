package breezeauth

import "time"

// Config defines settings for the Breeze authentication system
type Config struct {
	JWTSecret                   string
	JWTExpiration               time.Duration
	ResetTokenExpiration        time.Duration
	VerificationTokenExpiration time.Duration
	FrontendResetPasswordURL    string
	FrontendVerifyEmailURL      string
	Mailer                      Mailer
	RequireEmailVerification    bool
}

// DefaultConfig provides sensible production-ready defaults (using LogMailer)
func DefaultConfig() Config {
	return Config{
		JWTSecret:                   "change-this-secret-in-production",
		JWTExpiration:               24 * time.Hour,
		ResetTokenExpiration:        60 * time.Minute,
		VerificationTokenExpiration: 24 * time.Hour,
		FrontendResetPasswordURL:    "http://localhost:3000/reset-password",
		FrontendVerifyEmailURL:      "http://localhost:3000/verify-email",
		Mailer:                      NewLogMailer(),
		RequireEmailVerification:    false,
	}
}

