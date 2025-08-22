package db

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
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
		password_hash TEXT NOT NULL
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
		FOREIGN KEY (user_id) REFERENCES users(id)
    	FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
	);

	`
	_, err = DB.Exec(schema)
	if err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	return nil
}

func StartScheduler() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	log.Println("Database update scheduler started, updating every 30 seconds...")
	UpdateSessions()

	// Create a channel to listen for OS signals
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			UpdateSessions()
		case <-sigs:
			log.Println("Received interrupt signal, shutting down scheduler...")
			return
		}
	}
}

func UpdateSessions() error {
	_, err := DB.Exec("DELETE FROM sessions WHERE expiry < ?", time.Now())
	return err
}

func RegisterUser(user models.User) (*models.User, error) {
	_, err := DB.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", user.Username, user.PasswordHash)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return &models.User{}, models.AccountAlreadyExistsError
		}
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
	// Generate a cryptographically secure random token
	tokenBytes := make([]byte, 32) // 256-bit token
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}
	sessionToken := hex.EncodeToString(tokenBytes)

	// Compute expiry time
	expiry := time.Now().Add(time.Duration(expiryDurationHours) * time.Hour)

	// Insert into DB
	_, err := DB.Exec(
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
	row := DB.QueryRow("SELECT id, username, password_hash FROM users WHERE id = ?", userID)
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

func GetUserByUsername(username string) (*models.User, error) {
	row := DB.QueryRow("SELECT id, username, password_hash FROM users WHERE username = ?", username)
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

// InsertServerMember inserts a new ServerMember and links it to a session
func InsertServerMember(member models.ServerMember) error {
	query := `
		INSERT INTO server_joins (user_id, server_address, server_port, joined_username, session_id)
		VALUES (?, ?, ?, ?, ?)
	`
	_, err := DB.Exec(query, member.UserID, member.ServerAddress, member.ServerPort, member.JoinedUsername, member.SessionID)
	return err
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
