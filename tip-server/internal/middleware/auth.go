package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog/log"

	"tip-server/internal/db"
	"tip-server/internal/models"
)

// AuthConfig holds authentication middleware configuration
type AuthConfig struct {
	APIKey       string           // Static API key (for simple auth)
	Redis        *db.RedisClient  // Redis client for rate limiting
	RateLimit    int              // Requests per minute
	RateWindow   time.Duration    // Rate limit window
	SkipPaths    []string         // Paths to skip authentication
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(cfg AuthConfig) fiber.Handler {
	skipPaths := make(map[string]bool)
	for _, path := range cfg.SkipPaths {
		skipPaths[path] = true
	}

	return func(c *fiber.Ctx) error {
		path := c.Path()

		// Skip authentication for certain paths
		if skipPaths[path] {
			return c.Next()
		}

		// Also skip if path starts with skipped prefix
		for p := range skipPaths {
			if strings.HasPrefix(path, p) {
				return c.Next()
			}
		}

		// Get API key from header
		apiKey := c.Get("X-API-Key")
		if apiKey == "" {
			// Try Authorization header with Bearer
			auth := c.Get("Authorization")
			if strings.HasPrefix(auth, "Bearer ") {
				apiKey = strings.TrimPrefix(auth, "Bearer ")
			}
		}

		if apiKey == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(models.ErrorResponse{
				Error: "Missing API key",
				Code:  fiber.StatusUnauthorized,
			})
		}

		// Validate API key
		if cfg.APIKey != "" && apiKey != cfg.APIKey {
			log.Warn().
				Str("ip", c.IP()).
				Str("path", path).
				Msg("Invalid API key attempt")

			return c.Status(fiber.StatusUnauthorized).JSON(models.ErrorResponse{
				Error: "Invalid API key",
				Code:  fiber.StatusUnauthorized,
			})
		}

		// Rate limiting
		if cfg.Redis != nil && cfg.RateLimit > 0 {
			keyHash := hashAPIKey(apiKey)
			count, exceeded, err := cfg.Redis.IncrementRateLimit(
				context.Background(),
				keyHash,
				cfg.RateLimit,
				cfg.RateWindow,
			)

			if err != nil {
				log.Error().Err(err).Msg("Rate limit check failed")
				// Continue without rate limiting on error
			} else if exceeded {
				remaining, _ := cfg.Redis.GetRateLimitRemaining(context.Background(), keyHash, cfg.RateLimit)

				c.Set("X-RateLimit-Limit", string(rune(cfg.RateLimit)))
				c.Set("X-RateLimit-Remaining", string(rune(remaining)))

				return c.Status(fiber.StatusTooManyRequests).JSON(models.ErrorResponse{
					Error:   "Rate limit exceeded",
					Code:    fiber.StatusTooManyRequests,
					Details: "Please slow down your requests",
				})
			} else {
				c.Set("X-RateLimit-Limit", string(rune(cfg.RateLimit)))
				c.Set("X-RateLimit-Remaining", string(rune(cfg.RateLimit-int(count))))
			}
		}

		// Store API key hash in context for logging
		c.Locals("api_key_hash", hashAPIKey(apiKey))

		return c.Next()
	}
}

// hashAPIKey creates a SHA256 hash of the API key
func hashAPIKey(apiKey string) string {
	hash := sha256.Sum256([]byte(apiKey))
	return hex.EncodeToString(hash[:])
}

// RequestLogger creates a request logging middleware
func RequestLogger() fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()

		// Process request
		err := c.Next()

		// Log request
		duration := time.Since(start)
		status := c.Response().StatusCode()

		logEvent := log.Info()
		if status >= 400 {
			logEvent = log.Warn()
		}
		if status >= 500 {
			logEvent = log.Error()
		}

		logEvent.
			Str("method", c.Method()).
			Str("path", c.Path()).
			Int("status", status).
			Dur("duration", duration).
			Str("ip", c.IP()).
			Str("user_agent", c.Get("User-Agent")).
			Msg("HTTP request")

		return err
	}
}

// RecoverMiddleware recovers from panics
func RecoverMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		defer func() {
			if r := recover(); r != nil {
				log.Error().
					Interface("panic", r).
					Str("path", c.Path()).
					Msg("Recovered from panic")

				c.Status(fiber.StatusInternalServerError).JSON(models.ErrorResponse{
					Error: "Internal server error",
					Code:  fiber.StatusInternalServerError,
				})
			}
		}()

		return c.Next()
	}
}

// CORSMiddleware adds CORS headers
func CORSMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		c.Set("Access-Control-Allow-Origin", "*")
		c.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")

		if c.Method() == "OPTIONS" {
			return c.SendStatus(fiber.StatusNoContent)
		}

		return c.Next()
	}
}
