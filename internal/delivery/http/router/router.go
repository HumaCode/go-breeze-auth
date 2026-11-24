package router

import (
	"github.com/HumaCode/go-breeze-auth/breezeauth"
	"github.com/HumaCode/go-breeze-auth/config"
	"github.com/HumaCode/go-breeze-auth/internal/delivery/http/handler"
	"github.com/HumaCode/go-breeze-auth/pkg/response"

	"github.com/nelthaarion/breeze/v2"
	breezeMw "github.com/nelthaarion/breeze/v2/middlewares"
)

type RouterDependencies struct {
	Config      *config.Config
	AuthHandler *handler.AuthHandler
}

// SetupRouter registers all public and protected routes
func SetupRouter(deps *RouterDependencies) *breeze.Router {
	r := breeze.NewRouter()

	// Global Middlewares
	r.Use(breezeMw.RecoveryMiddleware())
	r.Use(breezeMw.LoggingMiddleware())
	r.Use(breezeMw.CORSMiddleware(breezeMw.CORSOptions{
		AllowOrigins:     "*",
		AllowMethods:     "GET, POST, PUT, DELETE, PATCH, OPTIONS",
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization",
		AllowCredentials: "true",
	}))

	// Health check
	r.Handle(breeze.GET, "/health", func(ctx *breeze.Context) error {
		return response.Success(ctx, 200, "Go Breeze Auth Service is healthy", map[string]string{
			"status": "online",
		})
	})

	// JWT Auth Middleware from reusable core package
	authMw := breezeauth.BreezeMiddleware(deps.Config.JWTSecret)

	// Public Auth Endpoints
	r.HandleBlocking(breeze.POST, "/api/v1/auth/register", deps.AuthHandler.Register)
	r.HandleBlocking(breeze.POST, "/api/v1/auth/login", deps.AuthHandler.Login)
	r.HandleBlocking(breeze.POST, "/api/v1/auth/forgot-password", deps.AuthHandler.ForgotPassword)
	r.HandleBlocking(breeze.POST, "/api/v1/auth/reset-password", deps.AuthHandler.ResetPassword)
	r.HandleBlocking(breeze.POST, "/api/v1/auth/verify-email", deps.AuthHandler.VerifyEmail)

	// Protected Auth Endpoints
	r.HandleBlocking(breeze.GET, "/api/v1/auth/me", deps.AuthHandler.GetMe, authMw)
	r.HandleBlocking(breeze.PUT, "/api/v1/auth/profile", deps.AuthHandler.UpdateProfile, authMw)
	r.HandleBlocking(breeze.PUT, "/api/v1/auth/password", deps.AuthHandler.UpdatePassword, authMw)
	r.HandleBlocking(breeze.POST, "/api/v1/auth/resend-verification", deps.AuthHandler.ResendVerification, authMw)
	r.HandleBlocking(breeze.POST, "/api/v1/auth/logout", deps.AuthHandler.Logout, authMw)

	return r
}
