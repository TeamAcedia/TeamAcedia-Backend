package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"teamacedia/backend/internal/api"
	"teamacedia/backend/internal/asset_manager"
	"teamacedia/backend/internal/config"
	"teamacedia/backend/internal/db"

	"github.com/rs/cors"
)

func main() {
	// Load config file
	cfg, err := config.LoadConfig("config.ini")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	config.Config = cfg

	// Initialize DB
	err = db.InitDB("teamacedia.db")
	if err != nil {
		log.Fatalf("Failed to initialize DB: %v", err)
	}
	go db.StartScheduler()

	// Load Cosmetics
	capesList, err := asset_manager.LoadCapes("./cosmetics/capes")
	if err != nil {
		log.Fatal(err)
	}
	asset_manager.Capes = capesList

	// Setup HTTP routes
	mux := http.NewServeMux()
	mux.HandleFunc("/api/register/", api.RegisterHandler)
	mux.HandleFunc("/api/register", api.RegisterHandler)
	mux.HandleFunc("/api/login/", api.LoginHandler)
	mux.HandleFunc("/api/login", api.LoginHandler)
	mux.HandleFunc("/api/verify-session/", api.VerifySessionHandler)
	mux.HandleFunc("/api/verify-session", api.VerifySessionHandler)
	mux.HandleFunc("/api/server/join/", api.JoinServerHandler)
	mux.HandleFunc("/api/server/join", api.JoinServerHandler)
	mux.HandleFunc("/api/server/leave/", api.LeaveServerHandler)
	mux.HandleFunc("/api/server/leave", api.LeaveServerHandler)
	mux.HandleFunc("/api/server/players/", api.GetServerPlayersHandler)
	mux.HandleFunc("/api/server/players", api.GetServerPlayersHandler)
	mux.HandleFunc("/api/cosmetics/capes/", api.GetCapesHandler)
	mux.HandleFunc("/api/cosmetics/capes", api.GetCapesHandler)
	mux.HandleFunc("/api/users/capes/", api.GetUserCapesHandler)
	mux.HandleFunc("/api/users/capes", api.GetUserCapesHandler)
	mux.HandleFunc("/api/users/capes/set_selected/", api.SetSelectedCapeHandler)
	mux.HandleFunc("/api/users/capes/set_selected", api.SetSelectedCapeHandler)
	mux.HandleFunc("/api/users/capes/get_selected/", api.GetSelectedCapeHandler)
	mux.HandleFunc("/api/users/capes/get_selected", api.GetSelectedCapeHandler)

	// Configure CORS middleware
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type"},
		AllowCredentials: false,
		MaxAge:           300,
	})

	handler := c.Handler(mux)

	srv := &http.Server{
		Addr:    ":22222",
		Handler: handler,
	}

	// Channel to listen for OS signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Run server in goroutine
	go func() {
		log.Println("TeamAcedia-Backend running on :22222")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Block until signal is received
	<-stop
	log.Println("Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited cleanly")
}
