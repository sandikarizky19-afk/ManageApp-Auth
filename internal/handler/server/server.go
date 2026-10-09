package server

import (
	"database/sql"
	"errors"
	"log"

	"auth-service/internal/controller"
	"auth-service/internal/handler"
	"auth-service/internal/middleware"
	"auth-service/internal/utils"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

type Server struct {
	App *fiber.App
	DB  *sql.DB
}

func New(db *sql.DB, jwtManager *utils.JWTManager) *Server {
	app := fiber.New(fiber.Config{
		AppName:      "Auth Service",
		ErrorHandler: errorHandler,
	})

	app.Use(logger.New())
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://localhost:3000, http://127.0.0.1:3000, http://localhost:5173, http://127.0.0.1:5173",
		AllowMethods:     "GET, POST, PUT, DELETE, OPTIONS, PATCH",
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization",
		AllowCredentials: true,
	}))
	app.Use(recover.New())

	s := &Server{
		App: app,
		DB:  db,
	}

	s.setupRoutes(jwtManager)

	return s
}

func errorHandler(c *fiber.Ctx, err error) error {
	var appErr utils.AppError
	if errors.As(err, &appErr) {
		return c.Status(appErr.Code).JSON(fiber.Map{
			"success": false,
			"message": appErr.Message,
		})
	}

	var fe *fiber.Error
	if errors.As(err, &fe) {
		return c.Status(fe.Code).JSON(fiber.Map{
			"success": false,
			"message": fe.Message,
		})
	}

	log.Printf("unhandled error: %v", err)
	return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
		"success": false,
		"message": "terjadi kesalahan pada server",
	})
}

func (s *Server) setupRoutes(jwtManager *utils.JWTManager) {
	authHandler := handler.NewAuthHandler(s.DB, jwtManager)

	profileController := controller.NewProfileController(s.DB, jwtManager)
	profileHandler := handler.NewProfileHandler(profileController)

	api := s.App.Group("/api/v1")
	api.Get("/health", s.healthCheck)
	api.Post("/auth/register", authHandler.Register)
	api.Post("/auth/login", authHandler.Login)
	api.Post("/auth/logout", authHandler.Logout)
	api.Post("/auth/refresh", authHandler.Refresh)
	api.Post("/auth/password/forgot", authHandler.RequestPasswordReset)
	api.Post("/auth/password/reset", authHandler.ResetPassword)

	// protected
	profile := api.Group("/profile", middleware.AuthRequired(jwtManager))
	profile.Get("/", profileHandler.GetProfileUser)
	profile.Put("/", profileHandler.UpdateProfileUser)
	profile.Put("/password", profileHandler.ChangePassword)
	profile.Get("/status", profileHandler.CheckAktifUser)
	profile.Patch("/deactivate", profileHandler.NonAktifUser)
}

func (s *Server) Listen(addr string) error {
	return s.App.Listen(addr)
}
