package repository

import (
	"auth-service/internal/controller"
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func NewPostgresDB(cfg *controller.Config) (*sql.DB, error) {
	dsn := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=%s",
		cfg.DBUser, cfg.DBPassword, cfg.DBHost, cfg.DBPort, cfg.DBName, cfg.DBSSLMode,
	)

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("gagal membuka koneksi database: %w", err)
	}

	db.SetMaxOpenConns(25)                  // Batas maksimal koneksi terbuka
	db.SetMaxIdleConns(5)                   // Batas koneksi idle
	db.SetConnMaxLifetime(15 * time.Minute) // Umur maksimal koneksi
	db.SetConnMaxIdleTime(5 * time.Minute)  // Batas waktu koneksi idle ditutup

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("gagal ping database: %w", err)
	}

	return db, nil
}
