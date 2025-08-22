package models

import (
	"time"
)

type User struct {
	ID           int
	Username     string
	PasswordHash string
}

type Session struct {
	ID           int
	UserID       int
	Expiry       time.Time
	SessionToken string
}

type Config struct {
	TokenValidDurationHours int
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
