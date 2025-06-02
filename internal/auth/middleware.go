package auth

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

type RateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	limit    int
	window   time.Duration
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		attempts: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	// Remove expired attempts
	var validAttempts []time.Time
	for _, t := range rl.attempts[ip] {
		if now.Sub(t) <= rl.window {
			validAttempts = append(validAttempts, t)
		}
	}
	rl.attempts[ip] = validAttempts

	// Check if under limit
	if len(rl.attempts[ip]) >= rl.limit {
		return false
	}

	// Record new attempt
	rl.attempts[ip] = append(rl.attempts[ip], now)
	return true
}

func RateLimitMiddleware(limiter *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr
			if !limiter.Allow(ip) {
				http.Error(w, "Too many requests", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

type key int

const userIDKey key = 0

func UserIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	userID, ok := ctx.Value(userIDKey).(uuid.UUID)
	return userID, ok
}

func NewAuthMiddleware(service *Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, err := service.repo.Authorize(r)
			if err != nil {
				log.Debug().
					Str("location", "NewAuthMiddleware").
					Str("error", err.Error()).
					Msg("Authorization failed")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			cookie, err := r.Cookie("session_token")
			if err != nil || cookie.Value == "" {
				http.Error(w, "Unauthorized: missing session", http.StatusUnauthorized)
				return
			}
			println("Found session_token:", cookie.Value)

			session, err := service.repo.GetSessionRowByToken(r.Context(), cookie.Value)
			if err != nil || time.Now().After(session.ExpiresAt) {
				http.Error(w, "Unauthorized: invalid session", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), userIDKey, userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
