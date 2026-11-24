package handler

import (
	"errors"
	"net/http"

	"github.com/HumaCode/go-breeze-auth/breezeauth"
	"github.com/HumaCode/go-breeze-auth/pkg/response"

	"github.com/nelthaarion/breeze/v2"
)

type AuthHandler struct {
	svc *breezeauth.Service
}

func NewAuthHandler(svc *breezeauth.Service) *AuthHandler {
	return &AuthHandler{svc: svc}
}

func getUserID(ctx *breeze.Context) (string, bool) {
	val, exists := ctx.Get("user_id")
	if !exists || val == nil {
		return "", false
	}
	id, ok := val.(string)
	return id, ok
}

// Register handles user registration
func (h *AuthHandler) Register(ctx *breeze.Context) error {
	var req breezeauth.RegisterRequest
	if err := ctx.Bind(&req); err != nil {
		return response.Error(ctx, http.StatusBadRequest, "Invalid request payload", err)
	}

	user, token, err := h.svc.Register(req)
	if err != nil {
		statusCode := http.StatusBadRequest
		if errors.Is(err, breezeauth.ErrUsernameTaken) || errors.Is(err, breezeauth.ErrEmailTaken) {
			statusCode = http.StatusConflict
		}
		return response.Error(ctx, statusCode, err.Error(), nil)
	}

	return response.Success(ctx, http.StatusCreated, "User registered successfully", map[string]interface{}{
		"user":  user,
		"token": token,
	})
}

// Login handles authentication by email or username
func (h *AuthHandler) Login(ctx *breeze.Context) error {
	var req breezeauth.LoginRequest
	if err := ctx.Bind(&req); err != nil {
		return response.Error(ctx, http.StatusBadRequest, "Invalid request payload", err)
	}

	user, token, err := h.svc.Login(req)
	if err != nil {
		statusCode := http.StatusUnauthorized
		if errors.Is(err, breezeauth.ErrUserInactive) || errors.Is(err, breezeauth.ErrEmailUnverified) {
			statusCode = http.StatusForbidden
		}
		return response.Error(ctx, statusCode, err.Error(), nil)
	}

	return response.Success(ctx, http.StatusOK, "Login successful", map[string]interface{}{
		"user":  user,
		"token": token,
	})
}

// ForgotPassword requests password reset email
func (h *AuthHandler) ForgotPassword(ctx *breeze.Context) error {
	var req breezeauth.ForgotPasswordRequest
	if err := ctx.Bind(&req); err != nil {
		return response.Error(ctx, http.StatusBadRequest, "Invalid request payload", err)
	}

	if err := h.svc.ForgotPassword(req); err != nil {
		return response.Error(ctx, http.StatusInternalServerError, "Failed to send reset link", err)
	}

	return response.Success(ctx, http.StatusOK, "If your email is registered, you will receive a password reset link shortly.", nil)
}

// ResetPassword validates token and sets new password
func (h *AuthHandler) ResetPassword(ctx *breeze.Context) error {
	var req breezeauth.ResetPasswordRequest
	if err := ctx.Bind(&req); err != nil {
		return response.Error(ctx, http.StatusBadRequest, "Invalid request payload", err)
	}

	if err := h.svc.ResetPassword(req); err != nil {
		return response.Error(ctx, http.StatusBadRequest, err.Error(), nil)
	}

	return response.Success(ctx, http.StatusOK, "Password has been reset successfully. Please login with your new password.", nil)
}

// VerifyEmail verifies email address
func (h *AuthHandler) VerifyEmail(ctx *breeze.Context) error {
	var req breezeauth.VerifyEmailRequest
	if err := ctx.Bind(&req); err != nil {
		return response.Error(ctx, http.StatusBadRequest, "Invalid request payload", err)
	}

	if err := h.svc.VerifyEmail(req); err != nil {
		return response.Error(ctx, http.StatusBadRequest, err.Error(), nil)
	}

	return response.Success(ctx, http.StatusOK, "Email verified successfully.", nil)
}

// ResendVerification re-sends verification link
func (h *AuthHandler) ResendVerification(ctx *breeze.Context) error {
	userID, ok := getUserID(ctx)
	if !ok || userID == "" {
		return response.Error(ctx, http.StatusUnauthorized, "Unauthorized", nil)
	}

	if err := h.svc.SendEmailVerification(userID); err != nil {
		return response.Error(ctx, http.StatusInternalServerError, "Failed to send verification email", err)
	}

	return response.Success(ctx, http.StatusOK, "Verification link sent successfully.", nil)
}

// GetMe retrieves the currently logged in user profile
func (h *AuthHandler) GetMe(ctx *breeze.Context) error {
	userID, ok := getUserID(ctx)
	if !ok || userID == "" {
		return response.Error(ctx, http.StatusUnauthorized, "Unauthorized", nil)
	}

	user, err := h.svc.GetProfile(userID)
	if err != nil {
		return response.Error(ctx, http.StatusNotFound, "User not found", err)
	}

	return response.Success(ctx, http.StatusOK, "Profile retrieved successfully", user)
}

// UpdateProfile updates name, username, and email
func (h *AuthHandler) UpdateProfile(ctx *breeze.Context) error {
	userID, ok := getUserID(ctx)
	if !ok || userID == "" {
		return response.Error(ctx, http.StatusUnauthorized, "Unauthorized", nil)
	}

	var req breezeauth.UpdateProfileRequest
	if err := ctx.Bind(&req); err != nil {
		return response.Error(ctx, http.StatusBadRequest, "Invalid request payload", err)
	}

	user, err := h.svc.UpdateProfile(userID, req)
	if err != nil {
		statusCode := http.StatusBadRequest
		if errors.Is(err, breezeauth.ErrUsernameTaken) || errors.Is(err, breezeauth.ErrEmailTaken) {
			statusCode = http.StatusConflict
		}
		return response.Error(ctx, statusCode, err.Error(), nil)
	}

	return response.Success(ctx, http.StatusOK, "Profile updated successfully", user)
}

// UpdatePassword updates password after checking current password
func (h *AuthHandler) UpdatePassword(ctx *breeze.Context) error {
	userID, ok := getUserID(ctx)
	if !ok || userID == "" {
		return response.Error(ctx, http.StatusUnauthorized, "Unauthorized", nil)
	}

	var req breezeauth.UpdatePasswordRequest
	if err := ctx.Bind(&req); err != nil {
		return response.Error(ctx, http.StatusBadRequest, "Invalid request payload", err)
	}

	if err := h.svc.UpdatePassword(userID, req); err != nil {
		return response.Error(ctx, http.StatusBadRequest, err.Error(), nil)
	}

	return response.Success(ctx, http.StatusOK, "Password updated successfully", nil)
}

// Logout clears the session/token acknowledgment
func (h *AuthHandler) Logout(ctx *breeze.Context) error {
	return response.Success(ctx, http.StatusOK, "Logged out successfully. Please discard your client token.", nil)
}
