package server

import (
	"database/sql"

	"auth-service/internal/handler"
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
		AppName: "Auth Service",
	})

	app.Use(logger.New())
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://localhost:3000, http://127.0.0.1:3000, http://localhost:5173, http://127.0.0.1:5173",
		AllowMethods:     "GET, POST, PUT, DELETE, OPTIONS",
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

func (s *Server) setupRoutes(jwtManager *utils.JWTManager) {
	authHandler := handler.NewAuthHandler(s.DB, jwtManager)
	api := s.App.Group("/api/v1")
	api.Get("/health", s.healthCheck)
	api.Post("/auth/register", authHandler.Register)
	api.Post("/auth/login", authHandler.Login)
	api.Post("/auth/logout", authHandler.Logout)
	api.Post("/auth/refresh", authHandler.Refresh)
}

func (s *Server) Listen(addr string) error {
	return s.App.Listen(addr)
}
