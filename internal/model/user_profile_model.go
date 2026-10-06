package model

import "time"


type Gender string

const (
	GenderMale   Gender = "male"
	GenderFemale Gender = "female"
)

type UserProfile struct {
	ID        int64      `json:"id"`
	UserID    int64      `json:"user_id"`
	FullName  string     `json:"full_name"`
	AvatarURL *string    `json:"avatar_url,omitempty"`
	Gender    *Gender    `json:"gender,omitempty"`
	BirthDate *time.Time `json:"birth_date,omitempty"`
	Address   *string    `json:"address,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

type UpdateProfileRequest struct {
	FullName  string  `json:"full_name"`
	AvatarURL *string `json:"avatar_url"`
	Gender    string  `json:"gender"`
	BirthDate string  `json:"birth_date"` // "YYYY-MM-DD"
	Address   *string `json:"address"`
}

type ProfileResponse struct {
	ID        int64      `json:"id"`
	UserID    int64      `json:"user_id"`
	FullName  string     `json:"full_name"`
	AvatarURL *string    `json:"avatar_url,omitempty"`
	Gender    *Gender    `json:"gender,omitempty"`
	BirthDate *time.Time `json:"birth_date,omitempty"`
	Address   *string    `json:"address,omitempty"`
	CreatedAt string     `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}