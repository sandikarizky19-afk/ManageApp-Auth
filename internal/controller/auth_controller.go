package controller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/mail"
	"regexp"
	"strings"

	"auth-service/internal/model"
	"auth-service/internal/repository"
	"auth-service/internal/utils"

	"golang.org/x/crypto/bcrypt"
)

// 400 → input/request tidak memenuhi validasi
// 409 → terjadi konflik dengan resource yang sudah ada
// 404 → resource tidak ditemukan
// 401 → belum terautentikasi
// 403 → sudah login tetapi tidak punya izin
// 500 → error internal server

var ErrInvalidCredentials = errors.New("username atau password salah")
var ErrTokenRequired = errors.New("token wajib diisi")

// TokenPair hasil login yang berisi access token dan refresh token.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// LoginRequest request payload dari handler.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// AuthController berisi logic autentikasi yang dipanggil oleh handler.
type AuthController struct {
	DB   *sql.DB
	JWT  *utils.JWTManager
	Repo *repository.UserRepository
}

func NewAuthController(db *sql.DB, jwt *utils.JWTManager) *AuthController {
	return &AuthController{
		DB:   db,
		JWT:  jwt,
		Repo: repository.NewUserRepository(db),
	}
}

func (c *AuthController) Login(ctx context.Context, req LoginRequest) (*TokenPair, error) {
	if strings.TrimSpace(req.Username) == "" || strings.TrimSpace(req.Password) == "" {
		return nil, errors.New("username dan password wajib diisi")
	}

	user, err := c.getUserByUsername(ctx, req.Username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("gagal mengambil user: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	accessToken, err := c.JWT.GenerateAccessToken(
		fmt.Sprintf("%d", user.ID),
		user.Username,
		user.Email,
		user.Role,
	)
	if err != nil {
		return nil, fmt.Errorf("gagal membuat access token: %w", err)
	}

	refreshToken, err := c.JWT.GenerateRefreshToken(
		fmt.Sprintf("%d", user.ID),
		user.Username,
		user.Email,
		user.Role,
	)
	if err != nil {
		return nil, fmt.Errorf("gagal membuat refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (c *AuthController) Logout(_ context.Context, accessToken, refreshToken string) error {
	if strings.TrimSpace(accessToken) == "" && strings.TrimSpace(refreshToken) == "" {
		return ErrTokenRequired
	}

	if strings.TrimSpace(accessToken) != "" {
		if _, err := c.JWT.ValidateAccessToken(accessToken); err != nil && !errors.Is(err, utils.ErrTokenExpired) {
			return fmt.Errorf("access token tidak valid: %w", err)
		}
	}

	if strings.TrimSpace(refreshToken) != "" {
		if _, err := c.JWT.ValidateRefreshToken(refreshToken); err != nil && !errors.Is(err, utils.ErrTokenExpired) {
			return fmt.Errorf("refresh token tidak valid: %w", err)
		}
	}

	return nil
}

func (c *AuthController) RefreshToken(ctx context.Context, refreshToken string) (*TokenPair, error) {
	if strings.TrimSpace(refreshToken) == "" {
		return nil, ErrTokenRequired
	}

	claims, err := c.JWT.ValidateRefreshToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("refresh token tidak valid: %w", err)
	}

	var userID int64
	if n, err := fmt.Sscanf(claims.UserID, "%d", &userID); err != nil || n != 1 {
		return nil, fmt.Errorf("id pengguna tidak valid dalam refresh token: %q", claims.UserID)
	}

	user, err := c.getUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("gagal mengambil user: %w", err)
	}

	accessToken, err := c.JWT.GenerateAccessToken(
		fmt.Sprintf("%d", user.ID),
		user.Username,
		user.Email,
		user.Role,
	)
	if err != nil {
		return nil, fmt.Errorf("gagal membuat access token baru: %w", err)
	}

	newRefreshToken, err := c.JWT.GenerateRefreshToken(
		fmt.Sprintf("%d", user.ID),
		user.Username,
		user.Email,
		user.Role,
	)
	if err != nil {
		return nil, fmt.Errorf("gagal membuat refresh token baru: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
	}, nil
}

func (c *AuthController) getUserByUsername(ctx context.Context, username string) (*model.User, error) {
	return c.Repo.GetUserByUsername(ctx, username)
}

func (c *AuthController) getUserByID(ctx context.Context, userID int64) (*model.User, error) {
	return c.Repo.GetUserByID(ctx, userID)
}

func (c *AuthController) createUser(ctx context.Context, user *model.User) error {
	return c.Repo.CreateUser(ctx, user)
}

func (c *AuthController) getUserByEmail(ctx context.Context, email string) (*model.User, error) {
	return c.Repo.GetUserByEmail(ctx, email)
}

var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_.]{3,32}$`)


type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func (r *RegisterRequest) normalize() {
	r.Username = strings.TrimSpace(r.Username)
	r.Email = strings.ToLower(strings.TrimSpace(r.Email))
}

func (r *RegisterRequest) validate() error {
	if !usernameRegex.MatchString(r.Username) {
		return utils.AppError{
			Code:    http.StatusBadRequest,
			Message: "username harus 3-32 karakter (huruf, angka, underscore, titik)",
		}
	}
	if _, err := mail.ParseAddress(r.Email); err != nil {
		return utils.AppError{Code: http.StatusBadRequest, Message: "format email tidak valid"}
	}
	// bcrypt hanya memproses 72 byte pertama, jadi batasi di sini.
	if len(r.Password) < 8 || len(r.Password) > 72 {
		return utils.AppError{
			Code:    http.StatusBadRequest,
			Message: "password harus 8-72 karakter",
		}
	}
	return nil
}


func (c *AuthController) RegisterUser(ctx context.Context, req RegisterRequest) (*model.User, error) {
	req.normalize()
	if err := req.validate(); err != nil {
		return nil, err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		slog.ErrorContext(ctx, "register: gagal hash password", "error", err)
		return nil, utils.AppError{
			Code:    http.StatusInternalServerError,
			Message: "terjadi kesalahan pada server",
		}
	}

	user := &model.User{
		Username: req.Username,
		Email:    req.Email,
		Password: string(hash),
		Role:     "user", // dipaksa di server, bukan dari input
	}

	if err := c.Repo.CreateUser(ctx, user); err != nil {
		switch {
		case errors.Is(err, repository.ErrUsernameTaken):
			return nil, utils.AppError{Code: http.StatusConflict, Message: "username sudah digunakan"}
		case errors.Is(err, repository.ErrEmailTaken):
			return nil, utils.AppError{Code: http.StatusConflict, Message: "email sudah digunakan"}
		default:
			slog.ErrorContext(ctx, "register: gagal membuat user", "error", err)
			return nil, utils.AppError{
				Code:    http.StatusInternalServerError,
				Message: "terjadi kesalahan pada server",
			}
		}
	}

	user.Password = "" // jangan pernah kembalikan hash ke pemanggil
	return user, nil
}

