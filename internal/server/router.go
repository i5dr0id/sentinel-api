package server

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

func NewRouter(h *Handlers) *fiber.App {
	app := fiber.New(fiber.Config{
		AppName:      "sentinel",
		ReadTimeout:  10 * 1e9,
		WriteTimeout: 30 * 1e9,
	})
	app.Use(recover.New())
	app.Use(logger.New())
	app.Use(cors.New(cors.Config{AllowOrigins: "*"}))

	api := app.Group("/api/v1")

	api.Get("/assets", h.Assets)
	api.Get("/summary", h.Summary)
	api.Get("/metrics", h.Metrics)

	api.Get("/alerts", h.ListAlerts)
	api.Get("/alerts/:id", h.GetAlert)
	api.Get("/alerts/:id/events", h.AlertEvents)
	api.Get("/alerts/:id/chain", h.AlertChain)
	api.Get("/alerts/:id/iocs", h.AlertIOCs)
	api.Patch("/alerts/:id/assign", h.Assign)
	api.Patch("/alerts/:id/status", h.SetStatus)
	api.Post("/alerts/:id/actions", h.Action)

	api.Get("/incidents", h.ListIncidents)
	api.Get("/incidents/:id", h.GetIncident)
	api.Post("/incidents/:id/assign", h.IncidentAssign)
	api.Post("/incidents/:id/contain", h.IncidentContain)

	api.Get("/containment", h.ListContainment)
	api.Post("/containment", h.DeployContainment)
	api.Post("/containment/:id/revoke", h.RevokeContainment)

	api.Get("/requests", h.ListRequests)
	api.Get("/requests/stream", h.StreamRequests)

	api.Post("/ingest", h.Ingest)

	app.Get("/health", h.Health)
	return app
}
