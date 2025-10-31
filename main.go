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
	"teamacedia/backend/internal/discord"

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

	// Middleware to limit request size globally
	const maxRequestBytes = int64(1 << 20) // 1 MB

	limitBodySize := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Early Content-Length check
			if r.ContentLength > maxRequestBytes && r.ContentLength != -1 {
				discord.LogEventf("Large request blocked: %s %s from %s (%d bytes)",
					r.Method, r.URL.Path, r.RemoteAddr, r.ContentLength)
				http.Error(w, "Request entity too large", http.StatusRequestEntityTooLarge)
				return
			}

			// Wrap body with MaxBytesReader to catch chunked requests
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)

			defer func() {
				if rec := recover(); rec != nil {
					discord.LogEventf("Recovered from panic: %v", rec)
					http.Error(w, "Internal server error", http.StatusInternalServerError)
				}
			}()

			// Run the next handler and detect read errors
			next.ServeHTTP(w, r)
		})
	}

	// Configure CORS middleware
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type"},
		AllowCredentials: false,
		MaxAge:           300,
	})

	// Chain middleware: CORS -> BodySizeLimiter -> Mux
	handler := c.Handler(limitBodySize(mux))

	srv := &http.Server{
		Addr:              ":22222",
		Handler:           handler,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		ReadHeaderTimeout: 3 * time.Second,
		MaxHeaderBytes:    1 << 12, // 4 KB header limit
	}

	// Channel to listen for OS signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Run server in goroutine
	go func() {
		discord.LogEvent("TeamAcedia-Backend running on :22222")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			discord.LogEventf("Failed to start server: %v", err)
		}
	}()

	// Block until signal is received
	<-stop
	discord.LogEvent("Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		discord.LogEventf("Server forced to shutdown: %v", err)
	}

	discord.LogEvent("Server exited cleanly")
}
