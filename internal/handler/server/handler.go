package server

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v2"
)

func (s *Server) healthCheck(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(c.Context(), 2*time.Second)
	defer cancel()
	if err := s.DB.PingContext(ctx); err != nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"status": "error",
			"db":     "unreachable",
		})
	}

	return c.JSON(fiber.Map{
		"status": "ok",
		"db":     "connected",
	})
}
