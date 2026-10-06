package handler

import (
	"auth-service/internal/controller"
	"auth-service/internal/model"
	"auth-service/internal/utils"
	"net/http"

	"github.com/gofiber/fiber/v2"
)

type ProfileHandler struct {
	controller *controller.ProfileController
}

func NewProfileHandler(c *controller.ProfileController) *ProfileHandler {
	return &ProfileHandler{
		controller: c,

	}
}

func (h *ProfileHandler) GetProfileUser(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(int64)
    if !ok {
        return &utils.AppError{
            Code:    http.StatusUnauthorized,
            Message: "Unauthorized",
        }
    }

	profile, err := h.controller.GetProfile(c.UserContext(), userID)
	if err != nil {
		return err
	}

	return c.JSON(fiber.Map{
		"success": true,
		"data": profile,
	})
}

func (h *ProfileHandler) UpdateProfileUser(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(int64)
	if !ok {
		return &utils.AppError{
			Code:    http.StatusUnauthorized,
			Message: "Unauthorized",
		}
	}

	var req model.UpdateProfileRequest
	if err := c.BodyParser(&req); err != nil {
		return utils.AppError{
			Code: http.StatusBadRequest,
			Message: "payload tidak valid",
		}
	}

	if err := h.controller.UpdateProfile(c.UserContext(), userID, req); err != nil {
		return err
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": "profil berhasil diperbarui",
	})
}

func (h *ProfileHandler) ChangePassword(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(int64)
	if !ok {
		return &utils.AppError{
			Code:    http.StatusUnauthorized,
			Message: "Unauthorized",
		}
	}

	var req model.ChangePasswordRequest
	if err := c.BodyParser(&req); err != nil {
		return utils.AppError{
			Code: http.StatusBadRequest,
			Message: "payload tidak valid",
		}
	}

	if err := h.controller.ChangePassword(c.UserContext(), userID, req); err != nil {
		return err
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": "password berhasil diperbarui",
	})
}