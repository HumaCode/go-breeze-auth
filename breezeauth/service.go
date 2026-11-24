package breezeauth

import (
	"errors"
	"fmt"
	"html"
	"net/url"
	"strings"
	"time"

	"gorm.io/gorm"
)

var (
	ErrUserNotFound           = errors.New("user not found")
	ErrInvalidCredentials      = errors.New("invalid identifier or password")
	ErrUserInactive           = errors.New("account is inactive")
	ErrAccountSuspended       = errors.New("account is temporarily suspended due to multiple failed login attempts")
	ErrEmailUnverified        = errors.New("email address has not been verified")
	ErrUsernameTaken          = errors.New("username is already taken")
	ErrEmailTaken             = errors.New("email is already registered")
	ErrInvalidOrExpiredToken  = errors.New("invalid or expired token")
	ErrInvalidCurrentPassword = errors.New("current password does not match")
	ErrEmptyFields            = errors.New("required fields cannot be empty")
)

// DTOs for Auth actions
type RegisterRequest struct {
	Name     string `json:"name"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Identifier string `json:"identifier"` // Email or Username
	Password   string `json:"password"`
	RememberMe bool   `json:"remember_me"` // Jika true, durasi token diperpanjang (default 30 hari)
}

// SuspendInfo detail status suspend untuk role dev / admin
type SuspendInfo struct {
	UserID              string     `json:"user_id"`
	Username            string     `json:"username"`
	Email               string     `json:"email"`
	IsActive            int        `json:"is_active"`
	IsSuspended         bool       `json:"is_suspended"`
	SuspendedUntil      *time.Time `json:"suspended_until,omitempty"`
	RemainingSeconds    int64      `json:"remaining_seconds,omitempty"`
	FailedLoginAttempts int        `json:"failed_login_attempts"`
	SuspendReason       string     `json:"suspend_reason"` // Keterangan tersembunyi
}

type ForgotPasswordRequest struct {
	Email string `json:"email"`
}

type ResetPasswordRequest struct {
	Email       string `json:"email"`
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

type VerifyEmailRequest struct {
	UserID string `json:"user_id"`
	Token  string `json:"token"`
}

type UpdateProfileRequest struct {
	Name     string `json:"name"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

type UpdatePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// Service provides all authentication workflows
type Service struct {
	db     *gorm.DB
	config Config
}

// New initializes the Breeze Auth service
func New(db *gorm.DB, cfg ...Config) *Service {
	c := DefaultConfig()
	if len(cfg) > 0 {
		c = cfg[0]
		if c.JWTExpiration <= 0 {
			c.JWTExpiration = 24 * time.Hour
		}
		if c.ResetTokenExpiration <= 0 {
			c.ResetTokenExpiration = 60 * time.Minute
		}
		if c.VerificationTokenExpiration <= 0 {
			c.VerificationTokenExpiration = 24 * time.Hour
		}
		if c.Mailer == nil {
			c.Mailer = NewLogMailer()
		}
	}
	return &Service{
		db:     db,
		config: c,
	}
}

// Register registers a new user, hashes the password, and returns the user & JWT token
func (s *Service) Register(req RegisterRequest) (*User, string, error) {
	// XSS Sanitization & normalisasi
	req.Name = html.EscapeString(strings.TrimSpace(req.Name))
	req.Username = html.EscapeString(strings.ToLower(strings.TrimSpace(req.Username)))
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	if req.Name == "" || req.Username == "" || req.Email == "" || req.Password == "" {
		return nil, "", ErrEmptyFields
	}

	// Check unique username
	var count int64
	if err := s.db.Model(&User{}).Where("username = ?", req.Username).Count(&count).Error; err != nil {
		return nil, "", err
	}
	if count > 0 {
		return nil, "", ErrUsernameTaken
	}

	// Check unique email
	if err := s.db.Model(&User{}).Where("email = ?", req.Email).Count(&count).Error; err != nil {
		return nil, "", err
	}
	if count > 0 {
		return nil, "", ErrEmailTaken
	}

	hash, err := HashPassword(req.Password)
	if err != nil {
		return nil, "", fmt.Errorf("failed to hash password: %w", err)
	}

	user := &User{
		Name:         req.Name,
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: hash,
		IsActive:     1,
	}

	if err := s.db.Create(user).Error; err != nil {
		return nil, "", err
	}

	// If verification is required, send verification email
	if s.config.RequireEmailVerification {
		_ = s.SendEmailVerification(user.ID)
	}

	token, err := GenerateJWT(s.config.JWTSecret, user, s.config.JWTExpiration)
	if err != nil {
		return user, "", err
	}

	return user, token, nil
}

// Login verifies credentials by email or username, checking throttling/suspend, activation & verification
func (s *Service) Login(req LoginRequest) (*User, string, error) {
	identifier := strings.ToLower(strings.TrimSpace(req.Identifier))
	if identifier == "" || req.Password == "" {
		return nil, "", ErrEmptyFields
	}

	var user User
	err := s.db.Where("email = ? OR username = ?", identifier, identifier).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, "", ErrInvalidCredentials
		}
		return nil, "", err
	}

	now := time.Now()

	// 1. Cek apakah user sedang dalam status suspend
	if user.SuspendedUntil != nil {
		if now.Before(*user.SuspendedUntil) {
			return nil, "", ErrAccountSuspended
		}
		// Masa suspend (misal 10 menit) telah terlewati, pulihkan status suspend otomatis
		user.SuspendedUntil = nil
		user.SuspendReason = ""
		user.FailedLoginAttempts = 0
		_ = s.db.Save(&user)
	}

	// 2. Verifikasi Password dengan Throttling (3x gagal -> suspend 10 menit)
	if !CheckPasswordHash(req.Password, user.PasswordHash) {
		user.FailedLoginAttempts++
		maxAttempts := s.config.MaxFailedLoginAttempts
		if maxAttempts <= 0 {
			maxAttempts = 3
		}

		if user.FailedLoginAttempts >= maxAttempts {
			suspendDuration := s.config.SuspendDuration
			if suspendDuration <= 0 {
				suspendDuration = 10 * time.Minute
			}
			suspendUntil := now.Add(suspendDuration)
			user.SuspendedUntil = &suspendUntil
			// Keterangan suspend tersembunyi yang hanya bisa dilihat role dev
			user.SuspendReason = fmt.Sprintf("Akun ditangguhkan otomatis oleh sistem: 3x gagal memasukkan password pada %s", now.Format("2006-01-02 15:04:05"))
			user.FailedLoginAttempts = 0
			_ = s.db.Save(&user)
			return nil, "", ErrAccountSuspended
		}

		_ = s.db.Save(&user)
		return nil, "", ErrInvalidCredentials
	}

	// 3. Cek apakah user aktif
	if user.IsActive == 0 {
		return nil, "", ErrUserInactive
	}

	// 4. Cek email verification jika diaktifkan
	if s.config.RequireEmailVerification && user.EmailVerifiedAt == nil {
		return nil, "", ErrEmailUnverified
	}

	// 5. Login berhasil: reset counter gagal login & bersihkan catatan suspend
	if user.FailedLoginAttempts > 0 || user.SuspendedUntil != nil || user.SuspendReason != "" {
		user.FailedLoginAttempts = 0
		user.SuspendedUntil = nil
		user.SuspendReason = ""
		_ = s.db.Save(&user)
	}

	// 6. Tentukan durasi token berdasarkan RememberMe
	jwtDuration := s.config.JWTExpiration
	if req.RememberMe {
		if s.config.JWTRememberMeExpiration > 0 {
			jwtDuration = s.config.JWTRememberMeExpiration
		} else {
			jwtDuration = 30 * 24 * time.Hour
		}
	}

	token, err := GenerateJWT(s.config.JWTSecret, &user, jwtDuration)
	if err != nil {
		return nil, "", err
	}

	return &user, token, nil
}

// ForgotPassword generates a secure reset token and delivers it via the configured mailer
func (s *Service) ForgotPassword(req ForgotPasswordRequest) error {
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" {
		return ErrEmptyFields
	}

	var user User
	err := s.db.Where("email = ?", email).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// For security, do not leak whether email exists
			return nil
		}
		return err
	}

	plainToken, err := GenerateRandomToken(32)
	if err != nil {
		return err
	}

	tokenHash := HashToken(plainToken)
	expiresAt := time.Now().Add(s.config.ResetTokenExpiration)

	// Save or replace token record for this email
	resetRecord := PasswordResetToken{
		Email:     email,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}

	if err := s.db.Save(&resetRecord).Error; err != nil {
		return err
	}

	// Build action URL
	resetURL := fmt.Sprintf("%s?email=%s&token=%s",
		s.config.FrontendResetPasswordURL,
		url.QueryEscape(email),
		plainToken,
	)

	return s.config.Mailer.SendPasswordReset(email, resetURL, plainToken)
}

// ResetPassword validates the token and updates the user's password
func (s *Service) ResetPassword(req ResetPasswordRequest) error {
	email := strings.ToLower(strings.TrimSpace(req.Email))
	token := strings.TrimSpace(req.Token)
	if email == "" || token == "" || req.NewPassword == "" {
		return ErrEmptyFields
	}

	var resetRecord PasswordResetToken
	err := s.db.Where("email = ?", email).First(&resetRecord).Error
	if err != nil {
		return ErrInvalidOrExpiredToken
	}

	// Verify expiration
	if time.Now().After(resetRecord.ExpiresAt) {
		_ = s.db.Delete(&resetRecord).Error
		return ErrInvalidOrExpiredToken
	}

	// Verify hash
	if HashToken(token) != resetRecord.TokenHash {
		return ErrInvalidOrExpiredToken
	}

	newHash, err := HashPassword(req.NewPassword)
	if err != nil {
		return err
	}

	// Update user password and purge used reset token in transaction
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&User{}).Where("email = ?", email).Update("password_hash", newHash).Error; err != nil {
			return err
		}
		return tx.Delete(&resetRecord).Error
	})
}

// SendEmailVerification creates a verification token and triggers the mailer
func (s *Service) SendEmailVerification(userID string) error {
	var user User
	if err := s.db.First(&user, "id = ?", userID).Error; err != nil {
		return ErrUserNotFound
	}

	plainToken, err := GenerateRandomToken(32)
	if err != nil {
		return err
	}

	tokenHash := HashToken(plainToken)
	expiresAt := time.Now().Add(s.config.VerificationTokenExpiration)

	record := EmailVerificationToken{
		UserID:    user.ID,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}

	if err := s.db.Save(&record).Error; err != nil {
		return err
	}

	verifyURL := fmt.Sprintf("%s?id=%s&token=%s",
		s.config.FrontendVerifyEmailURL,
		url.QueryEscape(user.ID),
		plainToken,
	)

	return s.config.Mailer.SendEmailVerification(user.Email, verifyURL, plainToken)
}

// VerifyEmail verifies the email address and marks EmailVerifiedAt
func (s *Service) VerifyEmail(req VerifyEmailRequest) error {
	if req.UserID == "" || req.Token == "" {
		return ErrEmptyFields
	}

	var record EmailVerificationToken
	if err := s.db.Where("user_id = ?", req.UserID).First(&record).Error; err != nil {
		return ErrInvalidOrExpiredToken
	}

	if time.Now().After(record.ExpiresAt) || HashToken(req.Token) != record.TokenHash {
		return ErrInvalidOrExpiredToken
	}

	now := time.Now()
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&User{}).Where("id = ?", req.UserID).Update("email_verified_at", &now).Error; err != nil {
			return err
		}
		return tx.Delete(&record).Error
	})
}

// GetProfile retrieves user data by ID
func (s *Service) GetProfile(userID string) (*User, error) {
	var user User
	if err := s.db.First(&user, "id = ?", userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

// UpdateProfile updates basic details (name, username, email) with XSS sanitization
func (s *Service) UpdateProfile(userID string, req UpdateProfileRequest) (*User, error) {
	user, err := s.GetProfile(userID)
	if err != nil {
		return nil, err
	}

	req.Name = html.EscapeString(strings.TrimSpace(req.Name))
	req.Username = html.EscapeString(strings.ToLower(strings.TrimSpace(req.Username)))
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	if req.Name != "" {
		user.Name = req.Name
	}

	if req.Username != "" && req.Username != user.Username {
		var count int64
		s.db.Model(&User{}).Where("username = ? AND id != ?", req.Username, userID).Count(&count)
		if count > 0 {
			return nil, ErrUsernameTaken
		}
		user.Username = req.Username
	}

	if req.Email != "" && req.Email != user.Email {
		var count int64
		s.db.Model(&User{}).Where("email = ? AND id != ?", req.Email, userID).Count(&count)
		if count > 0 {
			return nil, ErrEmailTaken
		}
		user.Email = req.Email
		if s.config.RequireEmailVerification {
			user.EmailVerifiedAt = nil // Requires reverification if email changed
		}
	}

	if err := s.db.Save(user).Error; err != nil {
		return nil, err
	}

	return user, nil
}

// UpdatePassword updates user password after verifying current password
func (s *Service) UpdatePassword(userID string, req UpdatePasswordRequest) error {
	if req.CurrentPassword == "" || req.NewPassword == "" {
		return ErrEmptyFields
	}

	user, err := s.GetProfile(userID)
	if err != nil {
		return err
	}

	if !CheckPasswordHash(req.CurrentPassword, user.PasswordHash) {
		return ErrInvalidCurrentPassword
	}

	newHash, err := HashPassword(req.NewPassword)
	if err != nil {
		return err
	}

	return s.db.Model(&User{}).Where("id = ?", userID).Update("password_hash", newHash).Error
}

// UnsuspendUser reactivates a suspended user account (dapat dipanggil oleh role dev/admin)
func (s *Service) UnsuspendUser(userID string) error {
	var user User
	if err := s.db.First(&user, "id = ?", userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserNotFound
		}
		return err
	}

	user.SuspendedUntil = nil
	user.SuspendReason = ""
	user.FailedLoginAttempts = 0
	user.IsActive = 1

	return s.db.Save(&user).Error
}

// GetSuspendDetails returns detailed suspension information including the hidden reason (khusus role dev)
func (s *Service) GetSuspendDetails(userID string) (*SuspendInfo, error) {
	var user User
	if err := s.db.First(&user, "id = ?", userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	now := time.Now()
	isSuspended := user.SuspendedUntil != nil && now.Before(*user.SuspendedUntil)
	var remainingSecs int64
	if isSuspended {
		remainingSecs = int64(time.Until(*user.SuspendedUntil).Seconds())
	}

	return &SuspendInfo{
		UserID:              user.ID,
		Username:            user.Username,
		Email:               user.Email,
		IsActive:            user.IsActive,
		IsSuspended:         isSuspended,
		SuspendedUntil:      user.SuspendedUntil,
		RemainingSeconds:    remainingSecs,
		FailedLoginAttempts: user.FailedLoginAttempts,
		SuspendReason:       user.SuspendReason,
	}, nil
}

