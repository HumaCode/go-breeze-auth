package breezeauth

import (
	"time"

	"gorm.io/gorm"
)

// BaseModel provides ULID primary key and standard timestamps
type BaseModel struct {
	ID        string    `gorm:"type:varchar(26);primaryKey" json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// BeforeCreate hooks ULID generator on insert if ID is empty
func (b *BaseModel) BeforeCreate(tx *gorm.DB) error {
	if b.ID == "" {
		b.ID = NewULID()
	}
	return nil
}

// User entity matching standard ecosystem conventions (compatible with go-rbac-menu)
type User struct {
	BaseModel
	Username            string     `gorm:"type:varchar(50);uniqueIndex;not null" json:"username"`
	Email               string     `gorm:"type:varchar(100);uniqueIndex;not null" json:"email"`
	PasswordHash        string     `gorm:"type:varchar(255);not null" json:"-"`
	Name                string     `gorm:"type:varchar(100);not null" json:"name"`
	EmailVerifiedAt     *time.Time `gorm:"index" json:"email_verified_at,omitempty"`
	IsActive            int        `gorm:"type:smallint;default:1;not null;index" json:"is_active"` // 1 = active, 0 = inactive
	FailedLoginAttempts int        `gorm:"type:int;default:0;not null" json:"failed_login_attempts"`
	SuspendedUntil      *time.Time `gorm:"index" json:"suspended_until,omitempty"`
	SuspendReason       string     `gorm:"type:varchar(255);default:''" json:"-"` // Tersembunyi dari JSON publik, hanya bisa dilihat role dev
}

func (User) TableName() string {
	return "users"
}

// PasswordResetToken holds secure hashed tokens for password resets
type PasswordResetToken struct {
	Email     string    `gorm:"type:varchar(100);primaryKey;index" json:"email"`
	TokenHash string    `gorm:"type:varchar(255);not null" json:"-"`
	ExpiresAt time.Time `gorm:"not null;index" json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

func (PasswordResetToken) TableName() string {
	return "password_reset_tokens"
}

// EmailVerificationToken holds secure hashed tokens for email verification
type EmailVerificationToken struct {
	UserID    string    `gorm:"type:varchar(26);primaryKey;index" json:"user_id"`
	TokenHash string    `gorm:"type:varchar(255);not null" json:"-"`
	ExpiresAt time.Time `gorm:"not null;index" json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

func (EmailVerificationToken) TableName() string {
	return "email_verification_tokens"
}

// AutoMigrate migrates all breeze authentication tables
func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&User{},
		&PasswordResetToken{},
		&EmailVerificationToken{},
	)
}

