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
	RewardNotFoundError       BackendError = "reward code not found"
	RewardMaxUsesError        BackendError = "reward code has reached its max uses"
	RewardAlreadyOwnedError   BackendError = "user already owns this reward"
	RewardAlreadyExistsError  BackendError = "reward code already exists"
)

type Cape struct {
	CapeID         string
	CapeTexture    string // base64
	CapePreview    string // base64
	CapeAnimLength int    // in frames
}

type RewardCode struct {
	CodeID      string // XXXX-YYYY
	CodeReward  string // id of the cosmetic it gives when used
	CodeUses    int    // number of total uses
	CodeMaxUses int    // 0 for infinite else #
	NewID       string // temp var for changing code id
}
