package controller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
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

	user, err := c.getUserByID(ctx, claims.UserID)
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

func (c *AuthController) getUserByID(ctx context.Context, userID string) (*model.User, error) {
	return c.Repo.GetUserByID(ctx, userID)
}

func (c *AuthController) RegisterUser(ctx context.Context, user *model.User) error {
	if strings.TrimSpace(user.Username) == "" || strings.TrimSpace(user.Password) == "" {
		return utils.AppError{
			Code:    http.StatusBadRequest,
			Message: "username dan password wajib diisi.",
		}
	}

	if strings.TrimSpace(user.Email) == "" {
		return utils.AppError{
			Code:    http.StatusBadRequest,
			Message: "email wajib diisi.",
		}
	}

	if strings.TrimSpace(user.Role) == "" {
		user.Role = "user"
	}

	existingByUsername, err := c.getUserByUsername(ctx, user.Username)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return utils.AppError{
			Code:    http.StatusInternalServerError,
			Message: "gagal memeriksa username",
		}
	}
	if existingByUsername != nil {
		return utils.AppError{
			Code:    http.StatusConflict,
			Message: "username sudah digunakan",
		}
	}

	existingByEmail, err := c.getUserByEmail(ctx, user.Email)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return utils.AppError{
			Code:    http.StatusInternalServerError,
			Message: "gagal memeriksa email",
		}
	}
	if existingByEmail != nil {
		return utils.AppError{
			Code:    http.StatusConflict,
			Message: "email sudah digunakan",
		}
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return utils.AppError{
			Code:    http.StatusInternalServerError,
			Message: "gagal menghash password. " + err.Error(),
		}
	}
	user.Password = string(hashedPassword)

	if err := c.createUser(ctx, user); err != nil {
		return utils.AppError{
			Code:    http.StatusInternalServerError,
			Message: "gagal membuat user baru",
		}
	}

	return nil
}

func (c *AuthController) createUser(ctx context.Context, user *model.User) error {
	return c.Repo.CreateUser(ctx, user)
}

func (c *AuthController) getUserByEmail(ctx context.Context, email string) (*model.User, error) {
	return c.Repo.GetUserByEmail(ctx, email)
}

type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

var (
	ErrUsernameTaken = errors.New("username sudah digunakan")
	ErrEmailTaken    = errors.New("email sudah digunakan")
)

