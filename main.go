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
)

func Home(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello from Backend! We are in %s. How are you?", r.URL.Path[0:])
}

func initEnvironment() (string, string, string, string, string) {
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")

	// Check for missing environment variables
	missing := []string{}
	if dbUser == "" {
		missing = append(missing, "DB_USER")
	}
	if dbPassword == "" {
		missing = append(missing, "DB_PASSWORD")
	}
	if dbName == "" {
		missing = append(missing, "DB_NAME")
	}
	if dbHost == "" {
		missing = append(missing, "DB_HOST")
	}
	if dbPort == "" {
		missing = append(missing, "DB_PORT")
	}

	if len(missing) > 0 {
		log.Fatalf("Missing required environment variables: %v", missing)
	}

	return dbUser, dbPassword, dbName, dbHost, dbPort
}

// main function to set up the HTTP server and routes
func main() {

	// Get database credentials from environment
	dbUser, dbPassword, dbName, dbHost, dbPort := initEnvironment()

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

	// Initialize tenant service
	tenantService := tenant.NewService(queries)

	// Initialize auth service with tenant service
	authService := auth.NewServiceWithTenant(repo, mailerService, tenantService)

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
		"GET /verify-email": func(w http.ResponseWriter, r *http.Request) {
			tenantMiddleware(http.HandlerFunc(userHandler.VerifyEmail)).ServeHTTP(w, r)
		},
		"GET /verify-email-otp": func(w http.ResponseWriter, r *http.Request) {
			tenantMiddleware(http.HandlerFunc(userHandler.VerifyEmailWithOTP)).ServeHTTP(w, r)
		},
		"POST /verify-email-otp": func(w http.ResponseWriter, r *http.Request) {
			tenantMiddleware(http.HandlerFunc(userHandler.VerifyEmailWithOTP)).ServeHTTP(w, r)
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
		"GET /admin/tenants":         tenantAdminHandler.GetTenants,
		"POST /admin/tenants":        tenantAdminHandler.CreateTenant,
		"GET /admin/tenants/{id}":    tenantAdminHandler.GetTenant,
		"PUT /admin/tenants/{id}":    tenantAdminHandler.UpdateTenant,
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

	// Get port from environment variable, default to 8080
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting server on :%s", port)
	// Start the server
	if err := http.ListenAndServe(":"+port, router.Handler()); err != nil {
		log.Fatalf("Server failed: %v", err)
	}

}
