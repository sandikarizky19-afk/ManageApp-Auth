package controller

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	AppHost    string
	AppPort    string
	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string
	DBName     string
	DBSSLMode  string
}

func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return fallback
}

// ini untuk password
func mustGetEnv(key string) string {
	val, ok := os.LookupEnv(key)
	if !ok || val == "" {
		log.Fatalf("environment variable %s wajib diisi", key)
	}
	return val
}

func LoadConfig() *Config {
	err := godotenv.Load()
	if err != nil {
		log.Println("file .env tidak ditemukan, nilai menggunakan default")
	}

	return &Config{
		DBHost:     getEnv("DB_HOST", "localhost"),
		DBPort:     getEnv("DB_PORT", "5432"),
		DBUser:     getEnv("DB_USER", "postgres"),
		DBPassword: getEnv("DB_PASSWORD", "postgres"),
		DBName:     getEnv("DB_NAME", "manage_app"),
		DBSSLMode:  getEnv("DB_SSL_MODE", "disable"),
		AppPort:    getEnv("APP_PORT", "8080"),
		AppHost:    getEnv("APP_IP", "0.0.0.0"),
	}
}
