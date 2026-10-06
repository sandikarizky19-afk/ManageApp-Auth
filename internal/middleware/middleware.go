package middleware

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"auth-service/internal/utils"

	"github.com/gofiber/fiber/v2"
)

func AuthRequired(jwt *utils.JWTManager) fiber.Handler {
	return func(c *fiber.Ctx) error {
		header := c.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			return utils.AppError{
				Code:    http.StatusUnauthorized,
				Message: "token tidak ditemukan",
			}
		}

		tokenStr := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))

		claims, err := jwt.ValidateAccessToken(tokenStr)
		if err != nil {
			msg := "token tidak valid"
			if errors.Is(err, utils.ErrTokenExpired) {
				msg = "token sudah kedaluwarsa"
			}
			return utils.AppError{Code: http.StatusUnauthorized, Message: msg}
		}

		// claims.UserID berupa string, konversi ke int64
		userID, err := strconv.ParseInt(claims.UserID, 10, 64)
		if err != nil {
			return utils.AppError{
				Code:    http.StatusUnauthorized,
				Message: "token tidak valid",
			}
		}

		c.Locals("user_id", userID) // int64
		c.Locals("role", claims.Role)
		return c.Next()
	}
}