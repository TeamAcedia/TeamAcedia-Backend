package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"teamacedia/backend/internal/asset_manager"
	"teamacedia/backend/internal/config"
	"teamacedia/backend/internal/db"
	"teamacedia/backend/internal/models"
)

// RegisterHandler allows registering a new user
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var data struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if data.Username == "" || data.Password == "" {
		http.Error(w, "Missing username or password", http.StatusBadRequest)
		return
	}

	user := models.User{
		Username:     data.Username,
		PasswordHash: data.Password,
	}
	_, err := db.RegisterUser(user)
	if err != nil {
		if err == models.AccountAlreadyExistsError {
			http.Error(w, "Account already exists", http.StatusConflict)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"message":"User registered successfully"}`))
}

// LoginHandler allows users to log in and receive a session token
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	// Handles user login.
	// Expects JSON with 'username' and 'password'.
	// The 'password' received here is assumed to be already hashed by the client.
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	username := creds.Username
	passwordHash := creds.Password
	if username == "" || passwordHash == "" {
		http.Error(w, "Missing username or password", http.StatusBadRequest)
		return
	}

	user, err := db.AuthenticateUser(username, passwordHash)
	if err != nil {
		if err == models.InvalidCredentialsError {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	session, err := db.CreateSession(user, config.Config.TokenValidDurationHours)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"session_token": session.SessionToken})
}

// VerifySessionHandler checks if a session token is valid and returns user name
func VerifySessionHandler(w http.ResponseWriter, r *http.Request) {
	// Handles session verification.
	// Expects a session token in the JSON request body under the key "token".
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	sessionToken := body.Token
	if sessionToken == "" {
		http.Error(w, "Missing session token", http.StatusUnauthorized)
		return
	}

	session, err := db.VerifySession(sessionToken)
	if err != nil {
		if err == models.InvalidSessionError {
			http.Error(w, "Invalid session", http.StatusUnauthorized)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	user, err := db.GetUserByID(session.UserID)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]string{"username": user.Username}); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// JoinServerHandler allows a user to announce they joined a server
func JoinServerHandler(w http.ResponseWriter, r *http.Request) {
	// Handles server join announcements.
	// Expects JSON with "token", "joined_username", "server_address", and "server_port".
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Token          string `json:"token"`
		JoinedUsername string `json:"joined_username"`
		ServerAddress  string `json:"server_address"`
		ServerPort     string `json:"server_port"` // changed to string
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if body.Token == "" || body.JoinedUsername == "" || body.ServerAddress == "" || body.ServerPort == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Verify the session token
	session, err := db.VerifySession(body.Token)
	if err != nil {
		if err == models.InvalidSessionError {
			http.Error(w, "Invalid session", http.StatusUnauthorized)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	// After decoding JSON
	portInt, err := strconv.Atoi(body.ServerPort)
	if err != nil {
		http.Error(w, "Invalid server port", http.StatusBadRequest)
		return
	}

	// Insert the server join
	member := models.ServerMember{
		UserID:         session.UserID,
		ServerAddress:  body.ServerAddress,
		ServerPort:     portInt, // string
		JoinedUsername: body.JoinedUsername,
		SessionID:      session.ID,
	}
	if err := db.InsertServerMember(member); err != nil {
		http.Error(w, "Failed to register server join", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Server join registered successfully"))
}

// LeaveServerHandler allows a user to remove themselves from a server
func LeaveServerHandler(w http.ResponseWriter, r *http.Request) {
	// Handles server leave announcements.
	// Expects JSON with "token", "joined_username", "server_address", and "server_port".
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Token          string `json:"token"`
		JoinedUsername string `json:"joined_username"`
		ServerAddress  string `json:"server_address"`
		ServerPort     string `json:"server_port"` // changed to string
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if body.Token == "" || body.JoinedUsername == "" || body.ServerAddress == "" || body.ServerPort == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Verify the session token
	session, err := db.VerifySession(body.Token)
	if err != nil {
		if err == models.InvalidSessionError {
			http.Error(w, "Invalid session", http.StatusUnauthorized)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	// After decoding JSON
	portInt, err := strconv.Atoi(body.ServerPort)
	if err != nil {
		http.Error(w, "Invalid server port", http.StatusBadRequest)
		return
	}

	// Remove the server join
	member := models.ServerMember{
		UserID:         session.UserID,
		ServerAddress:  body.ServerAddress,
		ServerPort:     portInt, // string
		JoinedUsername: body.JoinedUsername,
	}
	if err := db.RemoveServerMember(member); err != nil {
		http.Error(w, "Failed to remove server join", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Server leave registered successfully"))
}

// GetServerPlayersHandler returns all players currently joined to a server
func GetServerPlayersHandler(w http.ResponseWriter, r *http.Request) {
	// Handles fetching all players for a server.
	// Expects JSON with "token", "server_address", and "server_port".
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Token         string `json:"token"`
		ServerAddress string `json:"server_address"`
		ServerPort    string `json:"server_port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if body.Token == "" || body.ServerAddress == "" || body.ServerPort == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Verify the session token
	_, err := db.VerifySession(body.Token)
	if err != nil {
		if err == models.InvalidSessionError {
			http.Error(w, "Invalid session", http.StatusUnauthorized)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	// After decoding JSON
	portInt, err := strconv.Atoi(body.ServerPort)
	if err != nil {
		http.Error(w, "Invalid server port", http.StatusBadRequest)
		return
	}

	// Query all members for this server
	server := models.Server{
		ServerAddress: body.ServerAddress,
		ServerPort:    portInt,
	}
	members, err := db.GetServerMembersByAddress(&server)
	if err != nil {
		http.Error(w, "Failed to fetch server members", http.StatusInternalServerError)
		return
	}

	// Build a slice of maps with joined name and actual username
	playerList := make([]map[string]string, 0, len(members))
	for _, m := range members {
		user, err := db.GetUserByID(m.UserID)
		if err != nil {
			continue // skip this user if something goes wrong
		}
		playerList = append(playerList, map[string]string{
			"joined_name": m.JoinedUsername,
			"username":    user.Username,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string][]map[string]string{"players": playerList}); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

// GetCapesHandler verifies the session token and returns a list of capes.
func GetCapesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if body.Token == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Verify session
	_, err := db.VerifySession(body.Token)
	if err != nil {
		if err == models.InvalidSessionError {
			http.Error(w, "Invalid session", http.StatusUnauthorized)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	// Encode JSON directly to response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(asset_manager.Capes); err != nil {
		// At this point headers may already be sent, so we can’t change the status code
		// Just log the error
		log.Printf("failed to encode capes response: %v", err)
	}
}

// GetUserCapesHandler verifies the session token and returns a list of capes the user is allowed to use.
func GetUserCapesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if body.Token == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	session, err := db.VerifySession(body.Token)
	if err != nil {
		http.Error(w, "Invalid session", http.StatusUnauthorized)
		return
	}

	user, err := db.GetUserByID(session.UserID)
	if err != nil {
		http.Error(w, "User not found", http.StatusInternalServerError)
		return
	}

	capes, err := db.GetAllowedCapes(*user, *config.Config)
	if err != nil {
		http.Error(w, "Failed to get capes", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(capes)
}

// SetSelectedCapeHandler sets the user's currently selected cape.
func SetSelectedCapeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Token string `json:"token"`
		Cape  string `json:"cape"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if body.Token == "" || body.Cape == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	session, err := db.VerifySession(body.Token)
	if err != nil {
		http.Error(w, "Invalid session", http.StatusUnauthorized)
		return
	}

	user, err := db.GetUserByID(session.UserID)
	if err != nil {
		http.Error(w, "User not found", http.StatusInternalServerError)
		return
	}

	// Ensure the user is allowed to use this cape
	allowed, err := db.GetAllowedCapes(*user, *config.Config)
	if err != nil {
		http.Error(w, "Failed to get capes", http.StatusInternalServerError)
		return
	}

	isAllowed := false
	for _, c := range allowed {
		if c.CapeID == body.Cape {
			isAllowed = true
			break
		}
	}
	if !isAllowed {
		http.Error(w, "Cape not allowed", http.StatusForbidden)
		return
	}

	if err := db.SetSelectedCapeID(*user, body.Cape); err != nil {
		http.Error(w, "Failed to set cape", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Cape selected"})
}

// GetSelectedCapeHandler returns the user's currently active cape.
func GetSelectedCapeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Token string `json:"token"`
		User  string `json:"user"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if body.Token == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	session, err := db.VerifySession(body.Token)
	if err != nil {
		http.Error(w, "Invalid session", http.StatusUnauthorized)
		return
	}

	var cape string

	if body.User == "" {
		user, err := db.GetUserByID(session.UserID)
		if err != nil {
			http.Error(w, "User not found", http.StatusInternalServerError)
			return
		}

		cape, err = db.GetSelectedCapeID(*user)
		if err != nil {
			http.Error(w, "Failed to get selected cape", http.StatusInternalServerError)
			return
		}
	} else {
		user, err := db.GetUserByUsername(body.User)
		if err != nil {
			http.Error(w, "User not found", http.StatusInternalServerError)
			return
		}
		cape, err = db.GetSelectedCapeID(*user)
		if err != nil {
			http.Error(w, "Failed to get selected cape", http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"selected_cape": cape})
}

// GetUserAccountType returns the users account type
func GetUserAccountType(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Token string `json:"token"`
		User  string `json:"user"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if body.Token == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	session, err := db.VerifySession(body.Token)
	if err != nil {
		http.Error(w, "Invalid session", http.StatusUnauthorized)
		return
	}

	var account_type string

	if body.User == "" {
		user, err := db.GetUserByID(session.UserID)
		if err != nil {
			http.Error(w, "User not found", http.StatusInternalServerError)
			return
		}

		account_type = user.AccountType
	} else {
		user, err := db.GetUserByUsername(body.User)
		if err != nil {
			http.Error(w, "User not found", http.StatusInternalServerError)
			return
		}
		account_type = user.AccountType
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"account_type": account_type})
}

// SetUserAccountType sets the users account type
func SetUserAccountType(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Token       string `json:"token"`
		AccountType string `json:"account_type"`
		TargetUser  string `json:"target_username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if body.Token == "" || body.AccountType == "" || body.TargetUser == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	session, err := db.VerifySession(body.Token)
	if err != nil {
		http.Error(w, "Invalid session", http.StatusUnauthorized)
		return
	}

	user, err := db.GetUserByID(session.UserID)
	if err != nil {
		http.Error(w, "User not found", http.StatusInternalServerError)
		return
	}

	// Ensure the user is allowed to set account types
	target_user, err := db.GetUserByUsername(body.TargetUser)
	if err != nil {
		http.Error(w, "Target user not found", http.StatusInternalServerError)
		return
	}

	if user.AccountType != "Developer" {
		http.Error(w, "You do not have permission to do this", http.StatusForbidden)
		return
	}

	if err := db.SetUserAccountType(*target_user, body.AccountType); err != nil {
		http.Error(w, "Failed to set account type", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Set account type"})
}

// GetAllUsersHandler returns a list of all users (without passwords)
func GetAllUsersHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if body.Token == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Verify the session
	session, err := db.VerifySession(body.Token)
	if err != nil {
		http.Error(w, "Invalid session", http.StatusUnauthorized)
		return
	}

	// Get the requesting user
	user, err := db.GetUserByID(session.UserID)
	if err != nil {
		http.Error(w, "User not found", http.StatusInternalServerError)
		return
	}

	// Permission check
	if user.AccountType != "Developer" {
		http.Error(w, "You do not have permission to do this", http.StatusForbidden)
		return
	}

	// Fetch all users
	users, err := db.GetAllUsers()
	if err != nil {
		http.Error(w, "Failed to fetch users", http.StatusInternalServerError)
		return
	}

	// Strip passwords before returning
	type userResponse struct {
		ID          int    `json:"id"`
		Username    string `json:"username"`
		AccountType string `json:"account_type"`
	}

	var res []userResponse
	for _, u := range users {
		res = append(res, userResponse{
			ID:          u.ID,
			Username:    u.Username,
			AccountType: u.AccountType,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}
