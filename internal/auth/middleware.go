package auth

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

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
