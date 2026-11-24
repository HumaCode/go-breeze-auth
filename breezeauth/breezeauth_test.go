package breezeauth

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

type memoryMailer struct {
	lastEmail   string
	lastURL     string
	lastToken   string
	sendReset   int
	sendVerify  int
}

func (m *memoryMailer) SendPasswordReset(toEmail, resetURL, plainToken string) error {
	m.lastEmail = toEmail
	m.lastURL = resetURL
	m.lastToken = plainToken
	m.sendReset++
	return nil
}

func (m *memoryMailer) SendEmailVerification(toEmail, verifyURL, plainToken string) error {
	m.lastEmail = toEmail
	m.lastURL = verifyURL
	m.lastToken = plainToken
	m.sendVerify++
	return nil
}

func setupTestDB(t *testing.T) (*gorm.DB, *memoryMailer, *Service) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect sqlite: %v", err)
	}

	if err := AutoMigrate(db); err != nil {
		t.Fatalf("failed to auto migrate: %v", err)
	}

	mailer := &memoryMailer{}
	cfg := Config{
		JWTSecret:                   "test-secret-key-123",
		JWTExpiration:               2 * time.Hour,
		ResetTokenExpiration:        15 * time.Minute,
		VerificationTokenExpiration: 2 * time.Hour,
		FrontendResetPasswordURL:    "http://localhost:3000/reset-password",
		FrontendVerifyEmailURL:      "http://localhost:3000/verify-email",
		Mailer:                      mailer,
		RequireEmailVerification:    false,
	}

	svc := New(db, cfg)
	return db, mailer, svc
}

func TestRegisterAndLogin(t *testing.T) {
	_, _, svc := setupTestDB(t)

	// Register valid user
	user, token, err := svc.Register(RegisterRequest{
		Name:     "Budi Santoso",
		Username: "budi",
		Email:    "budi@example.com",
		Password: "secretpassword123",
	})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}
	if user.ID == "" || len(user.ID) != 26 {
		t.Errorf("expected 26 chars ULID, got: %s", user.ID)
	}
	if token == "" {
		t.Error("expected JWT token, got empty string")
	}

	// Test duplicate username
	_, _, err = svc.Register(RegisterRequest{
		Name:     "Budi Clone",
		Username: "budi",
		Email:    "different@example.com",
		Password: "secretpassword123",
	})
	if err != ErrUsernameTaken {
		t.Errorf("expected ErrUsernameTaken, got: %v", err)
	}

	// Test duplicate email
	_, _, err = svc.Register(RegisterRequest{
		Name:     "Budi Clone 2",
		Username: "budi2",
		Email:    "budi@example.com",
		Password: "secretpassword123",
	})
	if err != ErrEmailTaken {
		t.Errorf("expected ErrEmailTaken, got: %v", err)
	}

	// Test Login via Email
	loggedInUser, loginToken, err := svc.Login(LoginRequest{
		Identifier: "budi@example.com",
		Password:   "secretpassword123",
	})
	if err != nil {
		t.Fatalf("login via email failed: %v", err)
	}
	if loggedInUser.ID != user.ID || loginToken == "" {
		t.Errorf("login response mismatch")
	}

	// Test Login via Username
	loggedInUser2, _, err := svc.Login(LoginRequest{
		Identifier: "budi",
		Password:   "secretpassword123",
	})
	if err != nil {
		t.Fatalf("login via username failed: %v", err)
	}
	if loggedInUser2.ID != user.ID {
		t.Errorf("login response mismatch")
	}

	// Test Login invalid password
	_, _, err = svc.Login(LoginRequest{
		Identifier: "budi",
		Password:   "wrongpassword",
	})
	if err != ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials, got: %v", err)
	}
}

func TestForgotPasswordAndReset(t *testing.T) {
	_, mailer, svc := setupTestDB(t)

	// Register user
	user, _, err := svc.Register(RegisterRequest{
		Name:     "Dewi",
		Username: "dewi",
		Email:    "dewi@example.com",
		Password: "oldpassword",
	})
	if err != nil {
		t.Fatalf("failed to register: %v", err)
	}

	// Request Forgot Password
	err = svc.ForgotPassword(ForgotPasswordRequest{Email: user.Email})
	if err != nil {
		t.Fatalf("forgot password failed: %v", err)
	}
	if mailer.sendReset != 1 || mailer.lastToken == "" {
		t.Fatalf("expected mailer to send reset email, sent: %d", mailer.sendReset)
	}

	receivedToken := mailer.lastToken

	// Reset Password with wrong token
	err = svc.ResetPassword(ResetPasswordRequest{
		Email:       user.Email,
		Token:       "wrong-random-token",
		NewPassword: "newsecretpassword",
	})
	if err != ErrInvalidOrExpiredToken {
		t.Errorf("expected ErrInvalidOrExpiredToken, got: %v", err)
	}

	// Reset Password with correct token
	err = svc.ResetPassword(ResetPasswordRequest{
		Email:       user.Email,
		Token:       receivedToken,
		NewPassword: "newsecretpassword",
	})
	if err != nil {
		t.Fatalf("reset password failed: %v", err)
	}

	// Old password should now fail
	_, _, err = svc.Login(LoginRequest{
		Identifier: user.Email,
		Password:   "oldpassword",
	})
	if err != ErrInvalidCredentials {
		t.Errorf("expected old password to fail, got: %v", err)
	}

	// New password should succeed
	_, _, err = svc.Login(LoginRequest{
		Identifier: user.Email,
		Password:   "newsecretpassword",
	})
	if err != nil {
		t.Fatalf("login with new password failed: %v", err)
	}
}

func TestEmailVerification(t *testing.T) {
	db, mailer, _ := setupTestDB(t)

	cfg := Config{
		JWTSecret:                "test-secret",
		RequireEmailVerification: true,
		Mailer:                   mailer,
	}
	svc := New(db, cfg)

	user, _, err := svc.Register(RegisterRequest{
		Name:     "Citra",
		Username: "citra",
		Email:    "citra@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}

	// Should fail login because email is not verified yet
	_, _, err = svc.Login(LoginRequest{
		Identifier: "citra",
		Password:   "password123",
	})
	if err != ErrEmailUnverified {
		t.Errorf("expected ErrEmailUnverified, got: %v", err)
	}

	token := mailer.lastToken
	if token == "" {
		t.Fatal("expected verification token generated")
	}

	// Verify email
	err = svc.VerifyEmail(VerifyEmailRequest{
		UserID: user.ID,
		Token:  token,
	})
	if err != nil {
		t.Fatalf("verify email failed: %v", err)
	}

	// Login should succeed now
	_, _, err = svc.Login(LoginRequest{
		Identifier: "citra",
		Password:   "password123",
	})
	if err != nil {
		t.Fatalf("expected login to succeed after verification, got: %v", err)
	}
}

func TestUpdateProfileAndPassword(t *testing.T) {
	_, _, svc := setupTestDB(t)

	user, _, err := svc.Register(RegisterRequest{
		Name:     "Eko",
		Username: "eko",
		Email:    "eko@example.com",
		Password: "originalpassword",
	})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}

	// Update Profile
	updated, err := svc.UpdateProfile(user.ID, UpdateProfileRequest{
		Name:     "Eko Prasetyo",
		Username: "ekoprasetyo",
	})
	if err != nil {
		t.Fatalf("update profile failed: %v", err)
	}
	if updated.Name != "Eko Prasetyo" || updated.Username != "ekoprasetyo" {
		t.Errorf("profile not updated properly")
	}

	// Update Password wrong current password
	err = svc.UpdatePassword(user.ID, UpdatePasswordRequest{
		CurrentPassword: "wrongpassword",
		NewPassword:     "newcoolpassword",
	})
	if err != ErrInvalidCurrentPassword {
		t.Errorf("expected ErrInvalidCurrentPassword, got: %v", err)
	}

	// Update Password success
	err = svc.UpdatePassword(user.ID, UpdatePasswordRequest{
		CurrentPassword: "originalpassword",
		NewPassword:     "newcoolpassword",
	})
	if err != nil {
		t.Fatalf("update password failed: %v", err)
	}

	// Verify login with new password
	_, _, err = svc.Login(LoginRequest{
		Identifier: "ekoprasetyo",
		Password:   "newcoolpassword",
	})
	if err != nil {
		t.Fatalf("login failed after update password: %v", err)
	}
}

func TestAuthMiddleware(t *testing.T) {
	_, _, svc := setupTestDB(t)

	user, token, err := svc.Register(RegisterRequest{
		Name:     "Fajar",
		Username: "fajar",
		Email:    "fajar@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := ClaimsFromContext(r.Context())
		if !ok || claims.UserID != user.ID {
			http.Error(w, "unauthorized context", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	protectedHandler := AuthMiddleware("test-secret-key-123")(handler)

	// Request without header
	req := httptest.NewRequest("GET", "/protected", nil)
	rr := httptest.NewRecorder()
	protectedHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got: %d", rr.Code)
	}

	// Request with valid Bearer token
	req = httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	protectedHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got: %d", rr.Code)
	}
}

func TestLogMailer(t *testing.T) {
	var buf bytes.Buffer
	mailer := NewLogMailer(&buf)

	err := mailer.SendPasswordReset("test@example.com", "http://example.com/reset?token=xyz", "xyz")
	if err != nil {
		t.Fatalf("log mailer send password reset failed: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("test@example.com")) {
		t.Error("log mailer output missing email")
	}

	err = mailer.SendEmailVerification("test@example.com", "http://example.com/verify?token=abc", "abc")
	if err != nil {
		t.Fatalf("log mailer send email verification failed: %v", err)
	}
}

