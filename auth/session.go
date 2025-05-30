package auth

import (
	"errors"
	"fmt"
	"net/http"
)

var ErrAuth = errors.New("unauthorized access")

func Authorize(r *http.Request) error {
	username := r.FormValue("username")
	user, ok := users[username]
	if !ok {
		fmt.Println("User not found")
		return ErrAuth
	}
	fmt.Printf("Cookie: %v\n", r.Cookies())
	sessionToken, err := r.Cookie("session_token")
	if err != nil || sessionToken.Value == "" || sessionToken.Value != user.SessionToken {
		fmt.Println("Session token not found or invalid")
		return ErrAuth
	}
	// Get the CSRF token from the header instead of the cookie
	csrfToken := r.Header.Get("X-CSRF-Token")
	if csrfToken == "" || csrfToken != user.CSRFToken {
		fmt.Println("CSRF token not found or invalid")
		return ErrAuth
	}

	return nil
}
