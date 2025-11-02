package db

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"teamacedia/backend/internal/asset_manager"
	"teamacedia/backend/internal/config"
	"teamacedia/backend/internal/discord"
	"teamacedia/backend/internal/models"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var DB *sql.DB

func InitDB(path string) error {
	var err error
	DB, err = sql.Open("sqlite3", path)
	if err != nil {
		return err
	}

	// Enable foreign keys for SQLite
	_, err = DB.Exec("PRAGMA foreign_keys = ON;")
	if err != nil {
		return fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		account_type TEXT DEFAULT 'User'
	);
				
	CREATE TABLE IF NOT EXISTS sessions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		expiry TIMESTAMP NOT NULL,
		session_token TEXT NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id)
	);
	
	CREATE TABLE IF NOT EXISTS server_joins (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		server_address TEXT NOT NULL,
		server_port INTEGER NOT NULL,
		joined_username TEXT NOT NULL,
    	session_id INTEGER NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id),
    	FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS user_allowed_capes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		cape_id TEXT NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS user_selected_cape (
		user_id INTEGER NOT NULL UNIQUE,
		cape_id TEXT NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS reward_codes (
		code_id TEXT NOT NULL UNIQUE,
		code_reward TEXT NOT NULL,
		code_uses INTEGER NOT NULL,
		code_max_uses INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS ip_history (
		user_id INTEGER NOT NULL,
		ip_address TEXT NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS rate_limits (
		ip TEXT NOT NULL,
		action TEXT NOT NULL,
		count INTEGER NOT NULL DEFAULT 0,
		last_reset TIMESTAMP NOT NULL,
		PRIMARY KEY (ip, action)
	);

	`
	_, err = DB.Exec(schema)
	if err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	// Migration
	var count int
	err = DB.QueryRow(`
		SELECT COUNT(*) 
		FROM pragma_table_info('users') 
		WHERE name = 'account_type';
	`).Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check users table columns: %w", err)
	}

	if count == 0 {
		// Column doesn't exist, add it
		_, err = DB.Exec(`ALTER TABLE users ADD COLUMN account_type TEXT DEFAULT 'User';`)
		if err != nil {
			return fmt.Errorf("failed to add account_type column: %w", err)
		}

		// Backfill existing rows
		_, err = DB.Exec(`UPDATE users SET account_type = 'User' WHERE account_type IS NULL;`)
		if err != nil {
			return fmt.Errorf("failed to backfill account_type column: %w", err)
		}
	}

	return nil
}

func StartScheduler() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	discord.LogEvent("Database update scheduler started, updating every 30 seconds...")
	UpdateSessions()

	// Create a channel to listen for OS signals
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			UpdateSessions()
		case <-sigs:
			discord.LogEvent("Received interrupt signal, shutting down scheduler...")
			return
		}
	}
}

// UpdateSessions cleans up expired sessions and old rate limit records.
func UpdateSessions() error {
	now := time.Now()

	// delete expired sessions
	if _, err := DB.Exec("DELETE FROM sessions WHERE expiry < ?", now); err != nil {
		return fmt.Errorf("failed to delete expired sessions: %w", err)
	}

	// clean up old rate limit entries (older than 1 hour)
	cutoff := now.Add(-1 * time.Hour)
	if _, err := DB.Exec("DELETE FROM rate_limits WHERE last_reset < ?", cutoff); err != nil {
		return fmt.Errorf("failed to delete old rate limit entries: %w", err)
	}

	return nil
}

func CheckIPAccountLimit(ip string, maxAccounts int) (bool, error) {
	var count int
	err := DB.QueryRow("SELECT COUNT(*) FROM ip_history WHERE ip_address = ?", ip).Scan(&count)
	if err != nil {
		return false, models.DatabaseError
	}
	if count >= maxAccounts {
		return false, nil
	}
	return true, nil
}

func IncrementIPAccountCount(ip string, user models.User) error {
	_, err := DB.Exec("INSERT INTO ip_history (ip_address, user_id) VALUES (?, ?)", ip, user.ID)
	return err
}

func RegisterUser(user models.User, ip string) (*models.User, error) {
	allowed, err := CheckIPAccountLimit(ip, 3) // limit of 3 accounts per IP
	if err != nil {
		return &models.User{}, models.DatabaseError
	}
	if !allowed {
		return &models.User{}, models.TooManyAccountsError
	}

	_, err = DB.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", user.Username, user.PasswordHash)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return &models.User{}, models.AccountAlreadyExistsError
		}
		return &models.User{}, models.DatabaseError
	}

	createdUser, err := GetUserByUsername(user.Username) // get user to obtain ID
	if err != nil {
		return &models.User{}, models.DatabaseError
	}
	err = IncrementIPAccountCount(ip, *createdUser)
	if err != nil {
		return &models.User{}, models.DatabaseError
	}
	return GetUserByUsername(user.Username)
}

func AuthenticateUser(username, passwordHash string) (*models.User, error) {
	row := DB.QueryRow("SELECT id, username, password_hash FROM users WHERE username = ? AND password_hash = ?", username, passwordHash)
	var user models.User
	err := row.Scan(&user.ID, &user.Username, &user.PasswordHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, models.InvalidCredentialsError
		}
		return nil, models.DatabaseError
	}
	return &user, nil
}

func VerifySession(sessionToken string) (*models.Session, error) {
	row := DB.QueryRow("SELECT id, user_id, expiry, session_token FROM sessions WHERE session_token = ?", sessionToken)
	var session models.Session
	err := row.Scan(&session.ID, &session.UserID, &session.Expiry, &session.SessionToken)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, models.InvalidSessionError
		}
		return nil, models.DatabaseError
	}
	return &session, nil
}

func CreateSession(user *models.User, expiryDurationHours int) (*models.Session, error) {
	// Check how many sessions the user already has
	rows, err := DB.Query("SELECT id FROM sessions WHERE user_id = ? ORDER BY expiry ASC", user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to query sessions: %w", err)
	}
	defer rows.Close()

	var sessionIDs []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan session id: %w", err)
		}
		sessionIDs = append(sessionIDs, id)
	}

	// If the user already has 3 or more sessions, delete the oldest one
	if len(sessionIDs) >= 3 {
		oldestID := sessionIDs[0]
		_, err := DB.Exec("DELETE FROM sessions WHERE id = ?", oldestID)
		if err != nil {
			return nil, fmt.Errorf("failed to delete oldest session: %w", err)
		}
	}

	// Generate a cryptographically secure random token
	tokenBytes := make([]byte, 32) // 256-bit token
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}
	sessionToken := hex.EncodeToString(tokenBytes)

	// Compute expiry time
	expiry := time.Now().Add(time.Duration(expiryDurationHours) * time.Hour)

	// Insert into DB
	_, err = DB.Exec(
		"INSERT INTO sessions (user_id, expiry, session_token) VALUES (?, ?, ?)",
		user.ID, expiry, sessionToken,
	)
	if err != nil {
		return nil, models.DatabaseError
	}

	return &models.Session{
		UserID:       user.ID,
		Expiry:       expiry,
		SessionToken: sessionToken,
	}, nil
}

func ClearAllSessions(user *models.User) error {
	_, err := DB.Exec("DELETE FROM sessions WHERE user_id = ?", user.ID)
	if err != nil {
		return models.DatabaseError
	}
	return nil
}

func GetUserByID(userID int) (*models.User, error) {
	row := DB.QueryRow("SELECT id, username, password_hash, account_type FROM users WHERE id = ?", userID)
	var user models.User
	err := row.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.AccountType)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, models.InvalidCredentialsError
		}
		return nil, models.DatabaseError
	}
	return &user, nil
}

func GetUserByUsername(username string) (*models.User, error) {
	row := DB.QueryRow("SELECT id, username, password_hash, account_type FROM users WHERE username = ?", username)
	var user models.User
	err := row.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.AccountType)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, models.InvalidCredentialsError
		}
		return nil, models.DatabaseError
	}
	return &user, nil
}

// InsertServerMember inserts a new ServerMember and links it to a session
func InsertServerMember(member models.ServerMember) error {
	// Check if this session already has a server connection
	var count int
	err := DB.QueryRow(`
		SELECT COUNT(*) 
		FROM server_joins 
		WHERE session_id = ?
	`, member.SessionID).Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check existing session: %w", err)
	}

	if count > 0 {
		return models.ErrUserAlreadyConnected
	}

	// Insert the new record
	query := `
		INSERT INTO server_joins (user_id, server_address, server_port, joined_username, session_id)
		VALUES (?, ?, ?, ?, ?)
	`
	_, err = DB.Exec(query, member.UserID, member.ServerAddress, member.ServerPort, member.JoinedUsername, member.SessionID)
	if err != nil {
		return fmt.Errorf("failed to insert server member: %w", err)
	}

	return nil
}

// RemoveServerMember removes a user from a specific server using a ServerMember struct
func RemoveServerMember(member models.ServerMember) error {
	query := `
		DELETE FROM server_joins
		WHERE user_id = ? AND server_address = ? AND server_port = ? AND joined_username = ?
	`
	_, err := DB.Exec(query, member.UserID, member.ServerAddress, member.ServerPort, member.JoinedUsername)
	return err
}

// GetServerMembersByAddress retrieves all members who joined a given server address and port
func GetServerMembersByAddress(server *models.Server) ([]models.ServerMember, error) {
	query := `
		SELECT id, user_id, server_address, server_port, joined_username
		FROM server_joins
		WHERE server_address = ? AND server_port = ?
	`
	rows, err := DB.Query(query, server.ServerAddress, server.ServerPort)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var members []models.ServerMember
	for rows.Next() {
		var m models.ServerMember
		if err := rows.Scan(&m.ID, &m.UserID, &m.ServerAddress, &m.ServerPort, &m.JoinedUsername); err != nil {
			return nil, err
		}
		members = append(members, m)
	}

	return members, nil
}

// GetAllowedCapes returns all capes a user can access
func GetAllowedCapes(user models.User, cfg models.Config) ([]models.Cape, error) {
	allowedMap := make(map[string]models.Cape)

	// Add default capes from config
	for _, id := range strings.Split(cfg.DefaultCapeIDs, ",") {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}

		for _, cape := range asset_manager.Capes {
			if cape.CapeID == id {
				allowedMap[id] = cape
				break
			}
		}
	}

	// Query DB for user-specific capes
	rows, err := DB.Query("SELECT cape_id FROM user_allowed_capes WHERE user_id = ?", user.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var capeID string
		if err := rows.Scan(&capeID); err != nil {
			return nil, err
		}

		for _, cape := range asset_manager.Capes {
			if cape.CapeID == capeID {
				allowedMap[capeID] = cape
				break
			}
		}
	}

	// Convert map to slice
	result := make([]models.Cape, 0, len(allowedMap))
	for _, cape := range allowedMap {
		result = append(result, cape)
	}

	return result, nil
}

// GetSelectedCapeID returns the currently selected cape_id for the given user
func GetSelectedCapeID(user models.User) (string, error) {
	var capeID string
	err := DB.QueryRow("SELECT cape_id FROM user_selected_cape WHERE user_id = ?", user.ID).Scan(&capeID)
	if err != nil {
		if err == sql.ErrNoRows {
			return "crown", nil
		}
		return "crown", err
	}
	return capeID, nil
}

// SetSelectedCapeID sets or updates the selected cape_id for the given user
func SetSelectedCapeID(user models.User, capeID string) error {
	_, err := DB.Exec(`
		INSERT INTO user_selected_cape (user_id, cape_id) 
		VALUES (?, ?)
		ON CONFLICT(user_id) DO UPDATE SET cape_id = excluded.cape_id
	`, user.ID, capeID)
	return err
}

// SetUserAccountType sets the account_type for the given user
func SetUserAccountType(user models.User, accountType string) error {
	_, err := DB.Exec(`
		UPDATE users
		SET account_type = ?
		WHERE id = ?
	`, accountType, user.ID)
	return err
}

// GetAllUsers retrieves all users from the database
func GetAllUsers() ([]models.User, error) {
	rows, err := DB.Query("SELECT id, username, password_hash, account_type FROM users")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var user models.User
		err := rows.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.AccountType)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return users, nil
}

// GenerateUniqueRewardCode generates a code in XXXX-YYYY format and ensures it doesn't exist in the database
func GenerateUniqueRewardCode() (string, error) {
	const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, 8)

	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	for i := range 8 {
		b[i] = letters[int(b[i])%len(letters)]
	}

	code := fmt.Sprintf("%s%s%s%s-%s%s%s%s",
		string(b[0]), string(b[1]), string(b[2]), string(b[3]),
		string(b[4]), string(b[5]), string(b[6]), string(b[7]),
	)

	// Check if code already exists
	var exists int
	err = DB.QueryRow("SELECT 1 FROM reward_codes WHERE code_id = ?", code).Scan(&exists)
	if err != nil && err != sql.ErrNoRows {
		return "", fmt.Errorf("failed to check existing reward code: %w", err)
	}

	if exists == 1 {
		// Code exists, try again recursively
		return GenerateUniqueRewardCode()
	}

	return code, nil
}

// GetAllRewardCodes retrieves all reward codes from the database
func GetAllRewardCodes() ([]models.RewardCode, error) {
	rows, err := DB.Query("SELECT code_id, code_reward, code_uses, code_max_uses FROM reward_codes")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var codes []models.RewardCode
	for rows.Next() {
		var code models.RewardCode
		if err := rows.Scan(&code.CodeID, &code.CodeReward, &code.CodeUses, &code.CodeMaxUses); err != nil {
			return nil, err
		}
		codes = append(codes, code)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return codes, nil
}

// CreateRewardCode inserts a new reward code into the database
func CreateRewardCode(code models.RewardCode) error {
	_, err := DB.Exec(`
		INSERT INTO reward_codes (code_id, code_reward, code_uses, code_max_uses)
		VALUES (?, ?, ?, ?)
	`, code.CodeID, code.CodeReward, code.CodeUses, code.CodeMaxUses)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return models.RewardAlreadyExistsError
		}
		return models.DatabaseError
	}
	return nil
}

// UpdateRewardCode updates an existing reward code’s values
func UpdateRewardCode(code models.RewardCode) error {
	result, err := DB.Exec(`
		UPDATE reward_codes
		SET code_reward = ?, code_uses = ?, code_max_uses = ?, code_id = ?
		WHERE code_id = ?
	`, code.CodeReward, code.CodeUses, code.CodeMaxUses, code.NewID, code.CodeID)
	if err != nil {
		return models.DatabaseError
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return models.DatabaseError
	}

	if rowsAffected == 0 {
		return models.RewardNotFoundError
	}

	return nil
}

// RedeemRewardCode redeems a reward code for a user and adds the reward to their account
func RedeemRewardCode(codeID string, user models.User) error {
	tx, err := DB.Begin()
	if err != nil {
		return models.DatabaseError
	}
	defer tx.Rollback()

	var code models.RewardCode
	err = tx.QueryRow(`
		SELECT code_id, code_reward, code_uses, code_max_uses
		FROM reward_codes
		WHERE code_id = ?
	`, codeID).Scan(&code.CodeID, &code.CodeReward, &code.CodeUses, &code.CodeMaxUses)
	if err != nil {
		if err == sql.ErrNoRows {
			return models.RewardNotFoundError
		}
		return models.DatabaseError
	}

	if code.CodeMaxUses != 0 && code.CodeUses >= code.CodeMaxUses {
		return models.RewardMaxUsesError
	}

	_, err = tx.Exec(`
		UPDATE reward_codes
		SET code_uses = code_uses + 1
		WHERE code_id = ?
	`, codeID)
	if err != nil {
		return models.DatabaseError
	}

	var capes []models.Cape
	capes, err = GetAllowedCapes(user, *config.Config)
	if err != nil {
		return models.DatabaseError
	}

	for _, cape := range capes {
		if cape.CapeID == code.CodeReward {
			return models.RewardAlreadyOwnedError
		}
	}

	_, err = tx.Exec(`
		INSERT INTO user_allowed_capes (user_id, cape_id)
		VALUES (?, ?)
	`, user.ID, code.CodeReward)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return models.RewardAlreadyOwnedError
		}
		return models.DatabaseError
	}

	if err := tx.Commit(); err != nil {
		return models.DatabaseError
	}

	return nil
}

func GetRewardCodeByID(codeID string) (*models.RewardCode, error) {
	var code models.RewardCode
	err := DB.QueryRow(`
		SELECT code_id, code_reward, code_uses, code_max_uses
		FROM reward_codes
		WHERE code_id = ?
	`, codeID).Scan(&code.CodeID, &code.CodeReward, &code.CodeUses, &code.CodeMaxUses)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, models.RewardNotFoundError
		}
		return nil, models.DatabaseError
	}

	return &code, nil
}

func DeleteRewardCode(codeID string) error {
	result, err := DB.Exec("DELETE FROM reward_codes WHERE code_id = ?", codeID)
	if err != nil {
		return models.DatabaseError
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return models.DatabaseError
	}
	if rowsAffected == 0 {
		return models.RewardNotFoundError
	}

	return nil
}

// CheckAndUpdateRateLimit checks if the given IP/action pair is within the allowed requests per minute.
func CheckAndUpdateRateLimit(ip, action string, ratelimit int) (bool, error) {
	now := time.Now()
	var count int
	var lastReset time.Time

	err := DB.QueryRow(`
		SELECT count, last_reset FROM rate_limits WHERE ip = ? AND action = ?
	`, ip, action).Scan(&count, &lastReset)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// no record yet insert a new one starting at 1
			_, err = DB.Exec(`
				INSERT INTO rate_limits (ip, action, count, last_reset)
				VALUES (?, ?, 1, ?)
			`, ip, action, now)
			if err != nil {
				return false, fmt.Errorf("failed to insert rate limit record: %w", err)
			}
			return true, nil
		}
		return false, fmt.Errorf("failed to query rate limit: %w", err)
	}

	// reset if a minute has passed
	if now.Sub(lastReset) > time.Minute {
		count = 0
		lastReset = now
	}

	count++

	// update the record
	_, err = DB.Exec(`
		UPDATE rate_limits SET count = ?, last_reset = ? WHERE ip = ? AND action = ?
	`, count, lastReset, ip, action)
	if err != nil {
		return false, fmt.Errorf("failed to update rate limit: %w", err)
	}

	return count <= ratelimit, nil
}
