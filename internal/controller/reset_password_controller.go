package controller

import (
	"auth-service/internal/repository"
	"auth-service/internal/utils"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"net/smtp"
	"net/url"
	"os"
	"strings"
	"time"

	"net/http"

	"golang.org/x/crypto/bcrypt"
)

type ResetPasswordController struct {
	DB   *sql.DB
	JWT  *utils.JWTManager
	Repo *repository.UserRepository
}

func NewResetPasswordController(db *sql.DB, jwt *utils.JWTManager) *ResetPasswordController {
	return &ResetPasswordController{
		DB:   db,
		JWT:  jwt,
		Repo: repository.NewUserRepository(db),
	}
}

func (c *ResetPasswordController) ResetPassword(ctx context.Context, token string, newPassword string) error {
	if strings.TrimSpace(token) == "" {
		return utils.AppError{Code: http.StatusBadRequest, Message: "token wajib diisi"}
	}
	if len(newPassword) < 8 || len(newPassword) > 72 {
		return utils.AppError{Code: http.StatusBadRequest, Message: "password harus 8-72 karakter"}
	}

	hash := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])
	tx, err := c.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("gagal memulai reset password: %w", err)
	}
	defer tx.Rollback()

	var resetID int
	var targetUserID int
	err = tx.QueryRowContext(ctx, `
		SELECT id, user_id
		FROM password_resets
		WHERE token_hash = $1 AND expires_at > NOW() AND is_used = FALSE
		FOR UPDATE
	`, tokenHash).Scan(&resetID, &targetUserID)
	if errors.Is(err, sql.ErrNoRows) {
		return utils.AppError{Code: http.StatusBadRequest, Message: "tautan reset tidak valid atau sudah kedaluwarsa"}
	}
	if err != nil {
		return fmt.Errorf("gagal memeriksa token reset: %w", err)
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("gagal mengenkripsi password baru: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE users SET password = $1, updated_at = NOW() WHERE id = $2
	`, string(passwordHash), targetUserID); err != nil {
		return fmt.Errorf("gagal memperbarui password: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE password_resets SET is_used = TRUE WHERE id = $1
	`, resetID); err != nil {
		return fmt.Errorf("gagal menandai token reset: %w", err)
	}

	return tx.Commit()
}

func (c *ResetPasswordController) RequestPasswordReset(ctx context.Context, email string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if _, err := mail.ParseAddress(email); err != nil {
		return utils.AppError{Code: http.StatusBadRequest, Message: "format email tidak valid"}
	}

	user, err := c.Repo.GetUserByEmail(ctx, email)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("gagal mencari akun untuk reset password: %w", err)
	}

	rawToken := make([]byte, 32)
	if _, err := rand.Read(rawToken); err != nil {
		return fmt.Errorf("gagal membuat token reset: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(rawToken)
	tokenHashBytes := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(tokenHashBytes[:])

	tx, err := c.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("gagal memulai permintaan reset password: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
		UPDATE password_resets SET is_used = TRUE WHERE user_id = $1 AND is_used = FALSE
	`, user.ID); err != nil {
		return fmt.Errorf("gagal menonaktifkan token reset sebelumnya: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO password_resets (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`, user.ID, tokenHash, time.Now().Add(30*time.Minute)); err != nil {
		return fmt.Errorf("gagal menyimpan token reset: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("gagal menyimpan permintaan reset password: %w", err)
	}

	if err := c.sendResetEmail(user.Email, token); err != nil {
		slog.ErrorContext(ctx, "reset password: gagal mengirim email", "error", err)
		return utils.AppError{Code: http.StatusServiceUnavailable, Message: "email reset belum dapat dikirim. Silakan coba lagi nanti"}
	}
	return nil
}

func (c *ResetPasswordController) sendResetEmail(recipient, token string) error {
	host := strings.TrimSpace(os.Getenv("SMTP_HOST"))
	port := strings.TrimSpace(os.Getenv("SMTP_PORT"))
	username := os.Getenv("SMTP_USER")
	password := os.Getenv("SMTP_PASSWORD")
	from := strings.TrimSpace(os.Getenv("SMTP_FROM"))
	if host == "" || from == "" {
		return errors.New("SMTP_HOST dan SMTP_FROM wajib dikonfigurasi")
	}
	if port == "" {
		port = "587"
	}

	frontendURL := strings.TrimRight(strings.TrimSpace(os.Getenv("FRONTEND_URL")), "/")
	if frontendURL == "" {
		frontendURL = "http://localhost:3000"
	}
	resetURL := frontendURL + "/reset-password?token=" + url.QueryEscape(token)
	message := fmt.Sprintf("To: %s\r\nSubject: Reset password\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nGunakan tautan berikut untuk membuat password baru. Tautan berlaku selama 30 menit:\r\n%s\r\n", recipient, resetURL)

	var auth smtp.Auth
	if username != "" {
		auth = smtp.PlainAuth("", username, password, host)
	}
	return smtp.SendMail(host+":"+port, auth, from, []string{recipient}, []byte(message))
}
