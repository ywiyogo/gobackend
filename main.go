package main

import (
	"context"
	"fmt"
	"gobackend/internal/api"
	"gobackend/internal/auth"
	"gobackend/internal/db/sqlc"
	"gobackend/notes"
	"log"
	"net/http"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
)

func Home(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello from Backend! We are in %s. How are you?", r.URL.Path[0:])
}

func initEnvironment() (string, string, string, string, string) {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	return os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_NAME"), os.Getenv("DB_HOST"), os.Getenv("DB_PORT")
}

// main function to set up the HTTP server and routes
func main() {

	// Get database credentials from environment
	dbUser, dbPassword, dbName, dbHost, dbPort := initEnvironment()
	if dbUser == "" || dbPassword == "" || dbName == "" || dbHost == "" || dbPort == "" {
		log.Fatal("Database credentials are not set in environment variables")
	}

	log.Default().Println("Connecting to database...")
	connStr := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		dbUser, dbPassword, dbHost, dbPort, dbName)

	pool, err := pgxpool.New(context.Background(), connStr)
	if err != nil {
		log.Fatalf("Unable to create connection pool: %v", err)
	}
	defer pool.Close()

	queries := sqlc.New(pool)
	// Initialize repositories and services based on the repository pattern
	log.Default().Println("Setting up authentication repository and service...")
	if queries == nil {
		log.Fatal("Queries cannot be nil")
	}
	repo := auth.NewAuthRepository(queries)
	authService := auth.NewService(repo)
	userHandler := auth.NewHandler(authService)

	//Improved Architecture Using Handler Registry instead of direct handlers
	router := api.NewRouter(authService)
	router.AppendHandler("GET /", Home)

	routesAuth := map[string]http.HandlerFunc{
		"POST /register": userHandler.Register,
		"POST /login":    userHandler.Login,
		"POST /logout":   userHandler.Logout,
	}

	router.AppendHandlerFromMap(routesAuth)

	log.Default().Println("Setting up routes...")
	noteService := notes.NewService()
	noteManager := notes.NewNoteHTTPHandler(noteService)

	routesNotes := map[string]http.HandlerFunc{
		"GET /api/notes":         noteManager.HandleHTTPGet,
		"POST /api/notes":        noteManager.HandleHTTPPost,
		"GET /api/notes/{id}":    noteManager.HandleHTTPGetWithID,
		"PUT /api/notes/{id}":    noteManager.HandleHTTPPut,
		"DELETE /api/notes/{id}": noteManager.HandleHTTPDelete,
	}
	router.AppendHandlerFromMap(routesNotes)

	log.Println("Starting server on :8080")
	// Start the server
	if err := http.ListenAndServe(":8080", router.Handler()); err != nil {
		log.Fatalf("Server failed: %v", err)
	}

}
