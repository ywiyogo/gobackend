package main

import (
	"context"
	"fmt"
	"gobackend/internal/api"
	"gobackend/internal/auth"
	"gobackend/internal/db/sqlc"
	"gobackend/internal/health"
	"gobackend/internal/mailer"
	"gobackend/internal/notes"
	"gobackend/internal/tenant"
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

	// Initialize mailer service
	log.Default().Println("Initializing mailer service...")
	mailerService, err := mailer.NewMailer()
	if err != nil {
		log.Printf("Warning: Failed to initialize mailer service: %v", err)
		log.Printf("Falling back to mock mailer for development")
		mailerService = mailer.NewMockMailer()
	}

	// Show mailer configuration
	mailerConfig := mailerService.GetConfig()
	log.Printf("Mailer service initialized: %s", mailerConfig["service"])
	if mailerConfig["service"] != "mock" {
		log.Printf("SMTP Host: %s:%v", mailerConfig["host"], mailerConfig["port"])
		log.Printf("From Email: %s", mailerConfig["from_email"])
	}

	// Initialize repositories and services based on the repository pattern
	log.Default().Println("Setting up authentication repository and service...")
	if queries == nil {
		log.Fatal("Queries cannot be nil")
	}
	repo := auth.NewAuthRepository(queries)
	authService := auth.NewServiceWithMailer(repo, mailerService)

	// Initialize tenant service
	tenantService := tenant.NewService(queries)

	// Initialize health service
	healthHandler := health.NewHandler(tenantService)

	userHandler := auth.NewHandler(authService, tenantService)

	// Initialize tenant admin handler
	tenantAdminHandler := tenant.NewAdminHandler(tenantService)

	//Improved Architecture Using Handler Registry instead of direct handlers
	router := api.NewRouter(authService)
	router.AppendHandler("GET /", Home)

	// Health check routes (no middleware needed)
	routesHealth := map[string]http.HandlerFunc{
		"GET /health": healthHandler.Health,
		"GET /ready":  healthHandler.Ready,
		"GET /live":   healthHandler.Live,
	}

	router.AppendHandlerFromMapWithoutMiddleware(routesHealth)

	// Create tenant middleware
	tenantMiddleware := tenant.TenantMiddleware(tenantService)

	// Auth routes with tenant middleware
	routesAuth := map[string]http.HandlerFunc{
		"POST /register": func(w http.ResponseWriter, r *http.Request) {
			tenantMiddleware(http.HandlerFunc(userHandler.Register)).ServeHTTP(w, r)
		},
		"POST /login": func(w http.ResponseWriter, r *http.Request) {
			tenantMiddleware(http.HandlerFunc(userHandler.Login)).ServeHTTP(w, r)
		},
		"POST /logout": func(w http.ResponseWriter, r *http.Request) {
			tenantMiddleware(http.HandlerFunc(userHandler.Logout)).ServeHTTP(w, r)
		},
		"POST /verify-otp": func(w http.ResponseWriter, r *http.Request) {
			tenantMiddleware(http.HandlerFunc(userHandler.VerifyOTP)).ServeHTTP(w, r)
		},
	}

	router.AppendHandlerFromMap(routesAuth)

	// Protected dashboard route with tenant middleware
	dashboardWithTenant := func(w http.ResponseWriter, r *http.Request) {
		tenantMiddleware(http.HandlerFunc(api.Dashboard)).ServeHTTP(w, r)
	}
	router.AppendProtectedHandler("POST /dashboard", dashboardWithTenant)

	// Admin routes for tenant management (no tenant middleware needed)
	routesAdmin := map[string]http.HandlerFunc{
		"GET /admin/tenants":      tenantAdminHandler.GetTenants,
		"POST /admin/tenants":     tenantAdminHandler.CreateTenant,
		"GET /admin/tenants/{id}": tenantAdminHandler.GetTenant,
		"PUT /admin/tenants/{id}": tenantAdminHandler.UpdateTenant,
		"DELETE /admin/tenants/{id}": tenantAdminHandler.DeleteTenant,
	}
	router.AppendHandlerFromMapWithoutMiddleware(routesAdmin)

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
