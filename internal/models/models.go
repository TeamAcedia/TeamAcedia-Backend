package models

import (
	"time"
)

type User struct {
	ID           int
	Username     string
	PasswordHash string
	AccountType  string
}

type Session struct {
	ID           int
	UserID       int
	Expiry       time.Time
	SessionToken string
}

type Config struct {
	TokenValidDurationHours int
	DefaultCapeIDs          string
}

type ServerMember struct {
	ID             int
	UserID         int
	ServerAddress  string
	ServerPort     int
	JoinedUsername string
	SessionID      int
}

type Server struct {
	ServerAddress string
	ServerPort    int
}

type BackendError string

func (e BackendError) Error() string {
	return string(e)
}

const (
	AccountAlreadyExistsError BackendError = "account already exists"
	InvalidCredentialsError   BackendError = "invalid credentials"
	DatabaseError             BackendError = "database error"
	InvalidSessionError       BackendError = "invalid session"
)

type Cape struct {
	CapeID         string
	CapeTexture    string // base64
	CapePreview    string // base64
	CapeAnimLength int    // in frames
}
