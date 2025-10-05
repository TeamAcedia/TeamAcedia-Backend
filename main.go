package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"teamacedia/backend/internal/api"
	"teamacedia/backend/internal/asset_manager"
	"teamacedia/backend/internal/config"
	"teamacedia/backend/internal/db"

	"github.com/rs/cors"
)

// registerEndpoint registers a handler for both /path and /path/ automatically
func registerEndpoint(mux *http.ServeMux, path string, handler func(http.ResponseWriter, *http.Request)) {
	mux.HandleFunc(path, handler)
	if !strings.HasSuffix(path, "/") {
		mux.HandleFunc(path+"/", handler)
	}
}

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

	registerEndpoint(mux, "/api/register", api.RegisterHandler)
	registerEndpoint(mux, "/api/login", api.LoginHandler)
	registerEndpoint(mux, "/api/verify-session", api.VerifySessionHandler)
	registerEndpoint(mux, "/api/server/join", api.JoinServerHandler)
	registerEndpoint(mux, "/api/server/leave", api.LeaveServerHandler)
	registerEndpoint(mux, "/api/server/players", api.GetServerPlayersHandler)
	registerEndpoint(mux, "/api/cosmetics/capes", api.GetCapesHandler)
	registerEndpoint(mux, "/api/users/capes", api.GetUserCapesHandler)
	registerEndpoint(mux, "/api/users/capes/set_selected", api.SetSelectedCapeHandler)
	registerEndpoint(mux, "/api/users/capes/get_selected", api.GetSelectedCapeHandler)
	registerEndpoint(mux, "/api/users/set_account_type", api.SetUserAccountTypeHandler)
	registerEndpoint(mux, "/api/users/get_account_type", api.GetUserAccountTypeHandler)
	registerEndpoint(mux, "/api/users/get_all", api.GetAllUsersHandler)
	registerEndpoint(mux, "/api/rewards/create", api.CreateRewardCodeHandler)
	registerEndpoint(mux, "/api/rewards/update", api.UpdateRewardCodeHandler)
	registerEndpoint(mux, "/api/rewards/delete", api.DeleteRewardCodeHandler)
	registerEndpoint(mux, "/api/rewards/get_all", api.GetAllRewardCodesHandler)
	registerEndpoint(mux, "/api/rewards/redeem", api.RedeemRewardCodeHandler)

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
