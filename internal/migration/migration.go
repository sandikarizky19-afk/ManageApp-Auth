package migration

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func RunMigrations(db *sql.DB) error {
	migrationDir, err := resolveMigrationDir()
	if err != nil {
		return err
	}

	entries, err := os.ReadDir(migrationDir)
	if err != nil {
		return fmt.Errorf("gagal membaca direktori migrasi: %w", err)
	}

	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasSuffix(entry.Name(), ".sql") {
			files = append(files, entry.Name())
		}
	}
	sort.Strings(files)

	for _, fileName := range files {
		filePath := filepath.Join(migrationDir, fileName)
		content, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("gagal membaca file migrasi %s: %w", fileName, err)
		}

		if _, err := db.Exec(string(content)); err != nil {
			return fmt.Errorf("gagal menjalankan migrasi %s: %w", fileName, err)
		}
	}

	return nil
}

func resolveMigrationDir() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("gagal mendapatkan working directory: %w", err)
	}

	for i := 0; i < 10; i++ {
		candidate := filepath.Join(dir, "migrations", ".up")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return "", fmt.Errorf("direktori migrasi tidak ditemukan, pastikan file ada di %s", filepath.Join("migrations", ".up"))
}
