package server

import (
	"context"
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"

	"github.com/i5dr0id/sentinel-api/internal/alerts"
	"github.com/i5dr0id/sentinel-api/internal/config"
	"github.com/i5dr0id/sentinel-api/internal/containment"
	"github.com/i5dr0id/sentinel-api/internal/detect"
	"github.com/i5dr0id/sentinel-api/internal/edge"
	"github.com/i5dr0id/sentinel-api/internal/enrich"
	"github.com/i5dr0id/sentinel-api/internal/event"
	"github.com/i5dr0id/sentinel-api/internal/ingest"
	"github.com/i5dr0id/sentinel-api/internal/requests"
	"github.com/i5dr0id/sentinel-api/internal/store"
)

type App struct {
	Fiber    *fiber.App
	Pipeline *Pipeline
	Cleanups []func()
}

func Build(cfg *config.Config, log *zerolog.Logger) (*App, error) {
	ctx := context.Background()

	aStore, closeStore, err := store.NewAlertsStore(ctx, cfg, log)
	if err != nil {
		return nil, fmt.Errorf("init store: %w", err)
	}
	svc := alerts.NewService(aStore, log)
	ctr := containment.NewService(log)

	geo := enrich.Default(log)
	norm := ingest.NewNormalizer(geo)
	engine := detect.NewEngine(log)
	edgeEngine := edge.NewEngine(log)
	ring := requests.NewRing(4096)
	hub := requests.NewHub()

	raw := make(chan event.RawLog, 8192)
	pipeline := newPipeline(raw, norm, engine, edgeEngine, svc, ring, hub, log)
	pipeline.Start()

	handlers := &Handlers{
		cfg: cfg, log: log, svc: svc, ctr: ctr, edge: edgeEngine, ring: ring, hub: hub, pipeline: pipeline,
	}

	if cfg.Sim.Enabled {
		sim := ingest.NewSimulator(cfg.Sim, cfg.Assets, raw, log)
		sim.Start()
		if cfg.Store.Kind == "memory" {
			if err := svc.SeedDemo(); err != nil {
				log.Warn().Err(err).Msg("seed demo alerts failed")
			}
		}
	}
	if len(cfg.Tail.Paths) > 0 {
		tailer := ingest.NewTailer(cfg.Tail.Paths, cfg.Tail.Asset, raw, log)
		tailer.Start()
	}

	app := &App{
		Fiber:    NewRouter(handlers),
		Pipeline: pipeline,
		Cleanups: []func(){closeStore, pipeline.Stop},
	}
	return app, nil
}
