package auth

import (
	"fmt"
	"net/http"
	"time"
)

type Authentication struct {
	HashedPassword string
	SessionToken   string
	CSRFToken      string
}

var users = map[string]Authentication{}

func Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" || len(username) < 3 || len(password) < 6 {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	if _, exists := users[username]; exists {
		http.Error(w, "Username already exists", http.StatusConflict)
		return
	}
	// Calculate the hash of the password and store it in the users database
	hashPassword, _ := HashPassword(password)
	users[username] = Authentication{HashedPassword: hashPassword}
	fmt.Fprintf(w, "User %s registered successfully!", username)
}

func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	user, ok := users[username]
	if !ok {
		http.Error(w, "Invalid username", http.StatusUnauthorized)
		return
	}

	if !CheckPasswordHash(password, user.HashedPassword) {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}
	// Generate a session token and store it in the user's login data
	sessionToken, err := GenerateToken(32) // 32 bytes token
	if err != nil {
		http.Error(w, "Failed to generate session token", http.StatusInternalServerError)
		return
	}
	csrfToken, err := GenerateToken(32) // 32 bytes CSRF token
	if err != nil {
		http.Error(w, "Failed to generate CSRF session token", http.StatusInternalServerError)
		return
	}

	// Set cookies before writing any content to the response
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  time.Now().Add(time.Hour * 24), // Set cookie expiration time for 24 hours
		HttpOnly: true,                           // Prevent JavaScript access to the cookie
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Expires:  time.Now().Add(time.Hour * 24), // Set cookie expiration time for 24 hours
		HttpOnly: false,
	})

	// Update the user with the new session token
	user.SessionToken = sessionToken
	user.CSRFToken = csrfToken // Store CSRF token
	users[username] = user     // Update the user with the new session token

	// Write response content after setting cookies
	fmt.Fprintln(w, "Login successful for user:", username)
	fmt.Fprintf(w, "User %s logged in successfully!\n", username)
	fmt.Fprintln(w, "CSRF token: ", csrfToken)
	fmt.Fprintln(w, "Session token: ", sessionToken)

}

// protected function to handle requests to the protected resource
func Protected(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := Authorize(r); err != nil {
		http.Error(w, "Unauthorized access", http.StatusUnauthorized)
		return
	}
	username := r.FormValue("username")
	fmt.Fprintf(w, "CSRF validation successful! Protected resource accessed by user: %s", username)
}
func Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := Authorize(r); err != nil {
		http.Error(w, "Unauthorized access", http.StatusUnauthorized)
		return
	}
	// Clear the session token for the cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour), // Set cookie expiration time to the past
		HttpOnly: true,                       // Prevent JavaScript access to the cookie
	})
	// Clear the CSRF token for the cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour), // Set cookie expiration time to the past
		HttpOnly: false,
	})
	// Clear the session token in the user data
	username := r.FormValue("username")
	user := users[username]
	user.SessionToken = ""
	user.CSRFToken = ""    // Clear CSRF token
	users[username] = user // Update the user with the cleared session token
	fmt.Fprintf(w, "User %s logged out successfully!", username)
}
