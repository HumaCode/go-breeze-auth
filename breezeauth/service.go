package breezeauth

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"gorm.io/gorm"
)

var (
	ErrUserNotFound           = errors.New("user not found")
	ErrInvalidCredentials      = errors.New("invalid identifier or password")
	ErrUserInactive           = errors.New("account is inactive")
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
	req.Name = strings.TrimSpace(req.Name)
	req.Username = strings.ToLower(strings.TrimSpace(req.Username))
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

// Login verifies credentials by email or username, checking activation & verification
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

	if !CheckPasswordHash(req.Password, user.PasswordHash) {
		return nil, "", ErrInvalidCredentials
	}

	if user.IsActive == 0 {
		return nil, "", ErrUserInactive
	}

	if s.config.RequireEmailVerification && user.EmailVerifiedAt == nil {
		return nil, "", ErrEmailUnverified
	}

	token, err := GenerateJWT(s.config.JWTSecret, &user, s.config.JWTExpiration)
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

// UpdateProfile updates basic details (name, username, email)
func (s *Service) UpdateProfile(userID string, req UpdateProfileRequest) (*User, error) {
	user, err := s.GetProfile(userID)
	if err != nil {
		return nil, err
	}

	req.Name = strings.TrimSpace(req.Name)
	req.Username = strings.ToLower(strings.TrimSpace(req.Username))
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

