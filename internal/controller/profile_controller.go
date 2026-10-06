package controller

import (
	"auth-service/internal/model"
	"auth-service/internal/repository"
	"auth-service/internal/utils"
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type ProfileController struct {
	DB   *sql.DB
	JWT  *utils.JWTManager
	Repo *repository.UserRepository
}

func NewProfileController(db *sql.DB, jwt *utils.JWTManager) *ProfileController {
	return &ProfileController{
		DB:   db,
		JWT:  jwt,
		Repo: repository.NewUserRepository(db),
	}
}

func (c *ProfileController) GetProfile(ctx context.Context, userId int64) (*model.ProfileResponse, error) {
	getProfile, err := c.Repo.GetUserProfileByUserID(ctx, userId)
	if err != nil {
		return nil, utils.AppError{
			Code: http.StatusInternalServerError, 
			Message: "gagal mengambil data pengguna"}
	}

	return getProfile, nil
}

func (c *ProfileController) UpdateProfile(ctx context.Context, userID int64, req model.UpdateProfileRequest) error {
	if strings.TrimSpace(req.FullName) == "" {
		return utils.AppError{
			Code:    http.StatusBadRequest,
			Message: "nama lengkap wajib diisi",
		}
	}

	bd, err := time.Parse("2006-01-02", req.BirthDate)
	if err != nil {
		return utils.AppError{
			Code:    http.StatusBadRequest,
			Message: "format tanggal lahir harus YYYY-MM-DD",
		}
	}

	if bd.After(time.Now()) {
		return utils.AppError{
			Code:    http.StatusBadRequest,
			Message: "tanggal lahir tidak boleh di masa depan",
		}
	}

	err = c.Repo.UpdateUserProfile(ctx, userID, &req, bd)
	if errors.Is(err, sql.ErrNoRows) {
		return utils.AppError{Code: http.StatusNotFound, Message: "profil tidak ditemukan"}
	}
	return err // AppError dari repository diteruskan apa adanya
}

func (c *ProfileController) ChangePassword(ctx context.Context, userId int64, req model.ChangePasswordRequest) error {
	if len(req.NewPassword) < 8 {
		return utils.AppError{
			Code: http.StatusBadRequest, 
			Message: "password baru minimal 8 karakter",
		}
	}

	user, err := c.Repo.GetUserByID(ctx, userId)
	if err != nil {
		return utils.AppError{
			Code: http.StatusNotFound, 
			Message: "pengguna tidak ditemukan",
		}
	}

	if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.OldPassword)) != nil {
		return utils.AppError{
			Code: http.StatusBadRequest, 
			Message: "password saat ini salah",
		}
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return utils.AppError{
			Code: http.StatusInternalServerError, 
			Message: "gagal memproses password",
		}
	}

	return c.Repo.UpdatePassword(ctx, userId, string(hashed))
}