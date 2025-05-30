package main

import (
	"fmt"
	"gobackend/auth"
	"gobackend/notes"
	"log"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello from Backend! We are in %s.", r.URL.Path[0:])
}

// main function to set up the HTTP server and routes
func main() {
	mux := http.NewServeMux()

	noteService := notes.NewService()
	noteManager := notes.NewNoteHTTPHandler(noteService)

	mux.HandleFunc("/", handler) // Default route
	mux.HandleFunc("/register", auth.Register)
	mux.HandleFunc("/login", auth.Login)
	mux.HandleFunc("/logout", auth.Logout)
	mux.HandleFunc("/protected", auth.Protected)

	mux.HandleFunc("POST /api/notes", noteManager.HandleHTTPPost)
	mux.HandleFunc("GET /api/notes", noteManager.HandleHTTPGet)
	mux.HandleFunc("GET /api/notes/{id}", noteManager.HandleHTTPGetWithID)
	mux.HandleFunc("PUT /api/notes/{id}", noteManager.HandleHTTPPut)
	mux.HandleFunc("DELETE /api/notes/{id}", noteManager.HandleHTTPDelete)

	log.Println("Starting server on :8080")
	// Start the server
	err := http.ListenAndServe(":8080", mux)
	if err != nil {
		panic(err)
	}

}
