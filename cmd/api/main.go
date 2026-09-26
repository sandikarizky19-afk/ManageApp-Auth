package main

import (
	"auth-service/internal/controller"
	"auth-service/internal/handler/server"
	"auth-service/internal/migration"
	"auth-service/internal/utils"
	"auth-service/repository"
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	cfg := controller.LoadConfig()

	db, err := repository.NewPostgresDB(cfg)
	if err != nil {
		log.Fatalf("Gagal terhubung ke database: %v", err)
	}
	defer db.Close()
	log.Println("Berhasil terhubung ke database PostgreSQL!")

	if err := migration.RunMigrations(db); err != nil {
		log.Fatalf("Gagal menjalankan migrasi database: %v", err)
	}
	log.Println("Migrasi database selesai.")

	jwtManager, err := utils.NewJwtManager()
	if err != nil {
		log.Fatalf("Gagal inisialisasi JWT manager: %v", err)
	}

	srv := server.New(db, jwtManager)
	host := cfg.AppHost
	if host == "" {
		host = "0.0.0.0"
	}
	address := net.JoinHostPort(host, cfg.AppPort)

	go func() {
		if err := srv.Listen(address); err != nil {
			log.Fatalf("Gagal menjalankan server: %v", err)
		}
	}()
	log.Printf("Server auth berjalan di %s\n", address)

	// Tunggu sinyal shutdown (Ctrl+C atau kill)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Mematikan server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.App.ShutdownWithContext(ctx); err != nil {
		log.Fatalf("Gagal shutdown server dengan rapi: %v", err)
	}

	log.Println("Server auth berhasil dimatikan.")
}
