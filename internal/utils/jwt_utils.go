package utils

import (
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrTokenExpired   = errors.New("Token Expired")
	ErrTokenInvalid   = errors.New("Token Tidak Valid")
	ErrTokenMalformed = errors.New("Format Token Salah")
	ErrUnexpectedSign = errors.New("Signing Method Tidak Sesuai")
	ErrSecretNotSet   = errors.New("JWT Secret Belum di-set di Environment")
)

type TokenType string

const (
	AccessToken  TokenType = "access"
	RefreshToken TokenType = "refresh"
)

type Claims struct {
	UserID   string    `json:"user_id"`
	UserName string    `json:"user_name"`
	Email    string    `json:"email"`
	Role     string    `json:"role"`
	Type     TokenType `json:"type"`
	jwt.RegisteredClaims
}

// jwt manager untuk membungkus secret & durasi supaya tidak membaca os.getenv berulang
type JWTManager struct {
	accessSecret    []byte
	refreshSecret   []byte
	accessDuration  time.Duration
	refreshDuration time.Duration
	issuer          string
}

func NewJwtManager() (*JWTManager, error) {
	accessSecret := os.Getenv("JWT_ACCESS_SECRET")
	refreshSecret := os.Getenv("JWT_REFRESH_SECRET")

	if accessSecret == "" {
		accessSecret = "dev-access-secret-change-me"
	}
	if refreshSecret == "" {
		refreshSecret = "dev-refresh-secret-change-me"
	}

	return &JWTManager{
		accessSecret:    []byte(accessSecret),
		refreshSecret:   []byte(refreshSecret),
		accessDuration:  15 * time.Minute,   // access token umur pendek
		refreshDuration: 7 * 24 * time.Hour, // refresh token umur panjang
		issuer:          "manage-app-auth-service",
	}, nil

}

// randomJTI generate ID unik sederhana untuk klaim "jti".
func randomJTI() string {
	return time.Now().UTC().Format("20060102150405.000000000")
}

func (m *JWTManager) generateToken(userID, userName, email, role string, tt TokenType, secret []byte, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID:   userID,
		UserName: userName,
		Email:    email,
		Role:     role,
		Type:     tt,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now),
			ID:        randomJTI(), // jti unik, berguna kalau nanti mau implementasi blacklist/revoke
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

func (m *JWTManager) GenerateAccessToken(userID, userName, email, role string) (string, error) {
	return m.generateToken(userID, userName, email, role, AccessToken, m.accessSecret, m.accessDuration)
}

// GenerateRefreshToken membuat refresh token umur panjang (dipakai untuk minta access token baru).
func (m *JWTManager) GenerateRefreshToken(userID, userName, email, role string) (string, error) {
	return m.generateToken(userID, userName, email, role, RefreshToken, m.refreshSecret, m.refreshDuration)
}

// ValidateAccessToken memverifikasi access token: signature, expiry, dan tipe token.
func (m *JWTManager) ValidateAccessToken(tokenStr string) (*Claims, error) {
	return m.validateToken(tokenStr, m.accessSecret, AccessToken)
}

// ValidateRefreshToken memverifikasi refresh token.
func (m *JWTManager) ValidateRefreshToken(tokenStr string) (*Claims, error) {
	return m.validateToken(tokenStr, m.refreshSecret, RefreshToken)
}

func (m *JWTManager) validateToken(tokenStr string, secret []byte, expectedType TokenType) (*Claims, error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		// WAJIB: cek signing method, mencegah serangan "alg confusion"
		// (mis. token diganti pakai alg "none" atau RS256 dipaksa jadi HS256).
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrUnexpectedSign
		}
		return secret, nil
	})

	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenExpired):
			return nil, ErrTokenExpired
		case errors.Is(err, jwt.ErrTokenMalformed):
			return nil, ErrTokenMalformed
		default:
			return nil, ErrTokenInvalid
		}
	}

	if !token.Valid {
		return nil, ErrTokenInvalid
	}

	if claims.Type != expectedType {
		return nil, ErrTokenInvalid
	}

	return claims, nil
}
