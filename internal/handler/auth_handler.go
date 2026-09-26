package handler

import (
	"auth-service/internal/controller"
	"auth-service/internal/model"
	"auth-service/internal/utils"
	"database/sql"
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"
)

type AuthHandler struct {
	Controller *controller.AuthController
}

func NewAuthHandler(db *sql.DB, jwtManager *utils.JWTManager) *AuthHandler {
	return &AuthHandler{
		Controller: controller.NewAuthController(db, jwtManager),
	}
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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "payload tidak valid",
		})
	}

	tokens, err := h.Controller.Login(c.Context(), req)
	if err != nil {
		statusCode, message := mapAppError(err)
		if statusCode == fiber.StatusInternalServerError {
			statusCode = fiber.StatusUnauthorized
		}
		return c.Status(statusCode).JSON(fiber.Map{
			"error": message,
		})
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
		return c.Status(statusCode).JSON(fiber.Map{
			"error": message,
		})
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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "payload tidak valid",
		})
	}

	tokens, err := h.Controller.RefreshToken(c.Context(), payload.RefreshToken)
	if err != nil {
		statusCode, message := mapAppError(err)
		if statusCode == fiber.StatusInternalServerError {
			statusCode = fiber.StatusUnauthorized
		}
		return c.Status(statusCode).JSON(fiber.Map{
			"error": message,
		})
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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "payload tidak valid",
		})
	}

	user := &model.User{
		Username: req.Username,
		Email:    req.Email,
		Password: req.Password,
		Role:     req.Role,
	}

	if err := h.Controller.RegisterUser(c.Context(), user); err != nil {
		statusCode, message := mapAppError(err)
		return c.Status(statusCode).JSON(fiber.Map{
			"error": message,
		})
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
