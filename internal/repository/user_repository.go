package repository

import (
	"auth-service/internal/model"
	"auth-service/internal/utils"
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

type UserRepository struct {
	DB *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{DB: db}
}

func (r *UserRepository) GetUserByUsername(ctx context.Context, username string) (*model.User, error) {
	var user model.User

	query := `
		SELECT id, username, email, password, role, created_at, updated_at
		FROM users
		WHERE username = $1
		LIMIT 1
	`

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	err := r.DB.QueryRowContext(ctx, query, username).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.Password,
		&user.Role,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (r *UserRepository) GetUserByID(ctx context.Context, userID int64) (*model.User, error) {
	var user model.User

	query := `
		SELECT id, username, email, password, role, created_at, updated_at
		FROM users
		WHERE id = $1
		LIMIT 1
	`

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	err := r.DB.QueryRowContext(ctx, query, userID).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.Password,
		&user.Role,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (r *UserRepository) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
	var user model.User

	query := `
		SELECT id, username, email, password, role, created_at, updated_at
		FROM users
		WHERE email = $1
		LIMIT 1
	`

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	err := r.DB.QueryRowContext(ctx, query, email).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.Password,
		&user.Role,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (r *UserRepository) GetUserProfileByUserID(ctx context.Context, userID int64) (*model.ProfileResponse, error) {
	var p model.ProfileResponse
	var createdAt time.Time

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	err := r.DB.QueryRowContext(ctx,
		`select 
			id,
			user_id, 
			full_name, 
			avatar_url,
			gender,
			birth_date,
			address,
			created_at,
			updated_at
		from user_profiles
		where user_id = $1 limit 1`, userID).Scan(
		&p.ID,
		&p.UserID,
		&p.FullName,
		&p.AvatarURL,
		&p.Gender,
		&p.BirthDate,
		&p.Address,
		&createdAt,
		&p.UpdatedAt,
	)
	if err != nil {
		return nil, utils.AppError{
			Code:    http.StatusInternalServerError,
			Message: "gagal mengambil data profil pengguna",
		}
	}
	p.CreatedAt = createdAt.Format(time.RFC3339)

	return &p, nil
}

func (r *UserRepository) UpdateUserProfile(ctx context.Context, userID int64, req *model.UpdateProfileRequest, birthDate time.Time) error {
	// Gunakan satu context timeout saja untuk keseluruhan fungsi
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Menggunakan Upsert (ON CONFLICT).
	// Syarat: Kolom user_id di tabel user_profiles HARUS berupa UNIQUE atau PRIMARY KEY.
	query := `
		INSERT INTO user_profiles (user_id, full_name, avatar_url, gender, birth_date, address)
		VALUES ($1, $2, nullif($3::text, ''), $4, $5::date, nullif($6::text, ''))
		ON CONFLICT (user_id) 
		DO UPDATE SET
			full_name  = EXCLUDED.full_name,
			avatar_url = EXCLUDED.avatar_url,
			gender     = EXCLUDED.gender,
			birth_date = EXCLUDED.birth_date,
			address    = EXCLUDED.address,
			updated_at = NOW()
	`

	// Gunakan ExecContext karena kita tidak perlu membaca (Scan) data kembalian (seperti id).
	// Hapus simbol '&' pada variabel req karena Exec membutuhkan valuenya, bukan pointernya.
	_, err := r.DB.ExecContext(ctx, query,
		userID,
		req.FullName,
		req.AvatarURL,
		req.Gender,
		birthDate,
		req.Address,
	)

	if err != nil {
		// Log error asli di server Anda (opsional tapi disarankan untuk debugging)
		// log.Printf("Error Upsert Profile for user %d: %v", userID, err)

		return utils.AppError{
			Code:    http.StatusInternalServerError,
			Message: "Gagal menyimpan atau memperbarui data profil pengguna",
		}
	}

	return nil
}

func (r *UserRepository) UpdatePassword(ctx context.Context, userID int64, hashed string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	res, err := r.DB.ExecContext(ctx, `
		UPDATE users SET
			password   = $1,
			updated_at = NOW()
		WHERE id = $2`,
		hashed, userID,
	)
	if err != nil {
		return utils.AppError{
			Code:    http.StatusInternalServerError,
			Message: "gagal memperbarui kata sandi pengguna",
		}
	}

	if n, _ := res.RowsAffected(); n == 0 {
		return utils.AppError{
			Code:    http.StatusNotFound,
			Message: "pengguna tidak ditemukan",
		}
	}

	return nil
}

var (
	ErrUserNotFound  = errors.New("user tidak ditemukan")
	ErrUsernameTaken = errors.New("username sudah digunakan")
	ErrEmailTaken    = errors.New("email sudah digunakan")
)

func (r *UserRepository) CreateUser(ctx context.Context, user *model.User) error {

	query := `
		INSERT INTO users (username, email, password, role)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at, updated_at
	`

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	err := r.DB.QueryRowContext(ctx, query,
		user.Username,
		user.Email,
		user.Password,
		user.Role,
	).Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		switch pgErr.ConstraintName {
		case "idx_users_username":
			return utils.AppError{
				Code:    http.StatusConflict,
				Message: "username sudah digunakan",
			}
		case "idx_users_email":
			return utils.AppError{
				Code:    http.StatusConflict,
				Message: "email sudah digunakan",
			}
		}
	}
	return err
}

func (r *UserRepository) CheckAktifUser(ctx context.Context, userID int64) (*model.CheckAktifUserResponse, error) {
	user := &model.CheckAktifUserResponse{}

	var deletedAt sql.NullTime
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	err := r.DB.QueryRowContext(ctx, `	 
		select
			id,
			username,
			deleted_at
		from
			users
		where id = $1
		limit 1
	`, userID).Scan(
		&user.ID,
		&user.Username,
		&deletedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &utils.AppError{
				Code:    http.StatusNotFound,
				Message: "data pengguna tidak ditemukan",
			}
		}
		return nil, utils.AppError{
			Code:    http.StatusInternalServerError,
			Message: "gagal mengambil data pengguna. " + err.Error()}
	}
	if deletedAt.Valid {
		user.DeletedAt = &deletedAt.Time
	}
	return user, nil
}

func (r *UserRepository) NonAktifUser(ctx context.Context, userID int64) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	result, err := r.DB.ExecContext(ctx, `
		UPDATE users
		SET
			deleted_at = NOW(),
			updated_at = NOW()
		WHERE id = $1
		  AND deleted_at IS NULL
	`, userID)

	if err != nil {
		return &utils.AppError{
			Code:    http.StatusInternalServerError,
			Message: "gagal menonaktifkan pengguna",
		}
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return &utils.AppError{
			Code:    http.StatusInternalServerError,
			Message: "gagal memeriksa hasil perubahan pengguna",
		}
	}

	if rows == 0 {
		return &utils.AppError{
			Code:    http.StatusNotFound,
			Message: "pengguna tidak ditemukan atau sudah tidak aktif",
		}
	}

	return nil
}
