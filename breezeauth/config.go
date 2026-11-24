package breezeauth

import "time"

// Config defines settings for the Breeze authentication system
type Config struct {
	JWTSecret                   string
	JWTExpiration               time.Duration
	JWTRememberMeExpiration     time.Duration
	MaxFailedLoginAttempts      int
	SuspendDuration             time.Duration
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
		JWTRememberMeExpiration:     30 * 24 * time.Hour, // 30 hari jika remember me aktif
		MaxFailedLoginAttempts:      3,                   // Suspend setelah 3x gagal login
		SuspendDuration:             10 * time.Minute,    // Durasi suspend 10 menit
		ResetTokenExpiration:        60 * time.Minute,
		VerificationTokenExpiration: 24 * time.Hour,
		FrontendResetPasswordURL:    "http://localhost:3000/reset-password",
		FrontendVerifyEmailURL:      "http://localhost:3000/verify-email",
		Mailer:                      NewLogMailer(),
		RequireEmailVerification:    false,
	}
}

