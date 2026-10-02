package model

import "time"

type PasswordResetToken struct {
	ID        int
	UserID    int
	TokenHash string
	ExpiresAt time.Time
	IsUsed    bool
	CreatedAt time.Time
}
