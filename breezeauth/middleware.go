package breezeauth

import (
	"context"
	"net/http"
	"strings"

	"github.com/nelthaarion/breeze/v2"
)

type contextKey string

const userClaimsContextKey = contextKey("go_breeze_auth_claims")

// BreezeMiddleware provides an authentication middleware handler for the nelthaarion/breeze/v2 framework
func BreezeMiddleware(secret string) breeze.HandlerFunc {
	return func(ctx *breeze.Context) error {
		authHeader := ctx.GetHeader("Authorization")
		if authHeader == "" {
			ctx.Status(http.StatusUnauthorized)
			return ctx.JSON(map[string]interface{}{
				"success": false,
				"message": "Authorization header required",
			})
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			ctx.Status(http.StatusUnauthorized)
			return ctx.JSON(map[string]interface{}{
				"success": false,
				"message": "Invalid authorization header format (expected Bearer <token>)",
			})
		}

		claims, err := ValidateJWT(secret, parts[1])
		if err != nil {
			ctx.Status(http.StatusUnauthorized)
			return ctx.JSON(map[string]interface{}{
				"success": false,
				"message": "Invalid or expired token",
				"error":   err.Error(),
			})
		}

		ctx.Set("user", claims)
		ctx.Set("user_id", claims.UserID)
		ctx.Set("email", claims.Email)
		ctx.Set("username", claims.Username)

		return ctx.Next()
	}
}

// AuthMiddleware produces a standard net/http compatible middleware for JWT verification
func AuthMiddleware(secret string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
				http.Error(w, `{"error":"invalid authorization format, expected Bearer <token>"}`, http.StatusUnauthorized)
				return
			}

			claims, err := ValidateJWT(secret, parts[1])
			if err != nil {
				http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), userClaimsContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ClaimsFromContext extracts JWT Claims from standard request context
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	if ctx == nil {
		return nil, false
	}
	claims, ok := ctx.Value(userClaimsContextKey).(*Claims)
	return claims, ok
}

// UserIDFromContext extracts UserID string directly from request context
func UserIDFromContext(ctx context.Context) string {
	if claims, ok := ClaimsFromContext(ctx); ok && claims != nil {
		return claims.UserID
	}
	return ""
}

