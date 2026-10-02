package handler

import (
	"auth-service/internal/controller"
	"auth-service/internal/utils"
	"database/sql"
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"
)

type AuthHandler struct {
	Controller      *controller.AuthController
	ResetController *controller.ResetPasswordController
}

func NewAuthHandler(db *sql.DB, jwtManager *utils.JWTManager) *AuthHandler {
	return &AuthHandler{
		Controller:      controller.NewAuthController(db, jwtManager),
		ResetController: controller.NewResetPasswordController(db, jwtManager),
	}
}

func (h *AuthHandler) RequestPasswordReset(c *fiber.Ctx) error {
	var payload struct {
		Email string `json:"email"`
	}
	if err := c.BodyParser(&payload); err != nil {
		return utils.AppError{Code: fiber.StatusBadRequest, Message: "payload tidak valid"}
	}
	if err := h.ResetController.RequestPasswordReset(c.UserContext(), payload.Email); err != nil {
		statusCode, message := mapAppError(err)
		if statusCode == fiber.StatusInternalServerError {
			message = "terjadi kesalahan pada server"
		}
		return utils.AppError{Code: statusCode, Message: message}
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "jika email terdaftar, tautan reset password akan dikirim",
	})
}

func (h *AuthHandler) ResetPassword(c *fiber.Ctx) error {
	var payload struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if err := c.BodyParser(&payload); err != nil {
		return utils.AppError{Code: fiber.StatusBadRequest, Message: "payload tidak valid"}
	}
	if err := h.ResetController.ResetPassword(c.UserContext(), payload.Token, payload.NewPassword); err != nil {
		statusCode, message := mapAppError(err)
		if statusCode == fiber.StatusInternalServerError {
			message = "terjadi kesalahan pada server"
		}
		return utils.AppError{Code: statusCode, Message: message}
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "password berhasil diperbarui",
	})
}

func mapAppError(err error) (statusCode int, message string) {
	statusCode = fiber.StatusInternalServerError
	message = "internal server error"

	if err == nil {
		return fiber.StatusOK, ""
	}

	var appErr utils.AppError
	if errors.As(err, &appErr) {
		statusCode = appErr.Code
		message = appErr.Message
		return statusCode, message
	}

	message = err.Error()
	return statusCode, message
}

func (h *AuthHandler) Login(c *fiber.Ctx) error {
	var req controller.LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return utils.AppError{
			Code:    fiber.StatusBadRequest,
			Message: "payload tidak valid",
		}
	}

	tokens, err := h.Controller.Login(c.Context(), req)
	if err != nil {
		statusCode, message := mapAppError(err)
		if statusCode == fiber.StatusInternalServerError {
			statusCode = fiber.StatusUnauthorized
		}
		return utils.AppError{
			Code:    statusCode,
			Message: message,
		}
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "login berhasil",
		"data":    tokens,
	})
}

func (h *AuthHandler) Logout(c *fiber.Ctx) error {
	var payload struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}

	if err := c.BodyParser(&payload); err != nil {
		payload.AccessToken = extractBearerToken(c.Get("Authorization"))
	}

	if strings.TrimSpace(payload.AccessToken) == "" {
		payload.AccessToken = extractBearerToken(c.Get("Authorization"))
	}

	if err := h.Controller.Logout(c.Context(), payload.AccessToken, payload.RefreshToken); err != nil {
		statusCode, message := mapAppError(err)
		return utils.AppError{
			Code:    statusCode,
			Message: message,
		}
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "logout berhasil",
	})
}

func (h *AuthHandler) Refresh(c *fiber.Ctx) error {
	var payload struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := c.BodyParser(&payload); err != nil {
		return utils.AppError{
			Code:    fiber.StatusBadRequest,
			Message: "payload tidak valid",
		}
	}

	tokens, err := h.Controller.RefreshToken(c.Context(), payload.RefreshToken)
	if err != nil {
		statusCode, message := mapAppError(err)
		if statusCode == fiber.StatusInternalServerError {
			statusCode = fiber.StatusUnauthorized
		}
		return utils.AppError{
			Code:    statusCode,
			Message: message,
		}
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "token berhasil diperbarui",
		"data":    tokens,
	})
}

func extractBearerToken(authHeader string) string {
	const prefix = "Bearer "
	if strings.HasPrefix(authHeader, prefix) {
		return strings.TrimSpace(strings.TrimPrefix(authHeader, prefix))
	}
	return ""
}

func (h *AuthHandler) Register(c *fiber.Ctx) error {
	var req controller.RegisterRequest
	if err := c.BodyParser(&req); err != nil {
		return utils.AppError{
			Code:    fiber.StatusBadRequest,
			Message: "payload tidak valid",
		}
	}

	// Controller yang membentuk model.User dan memaksa Role = "user".
	user, err := h.Controller.RegisterUser(c.UserContext(), req)
	if err != nil {
		statusCode, message := mapAppError(err)
		return utils.AppError{
			Code:    statusCode,
			Message: message,
		}
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message": "registrasi berhasil",
		"data": fiber.Map{
			"id":       user.ID,
			"username": user.Username,
			"email":    user.Email,
			"role":     user.Role,
		},
	})
}
