package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/i5dr0id/sentinel-api/internal/config"
	"github.com/i5dr0id/sentinel-api/internal/logging"
	"github.com/i5dr0id/sentinel-api/internal/server"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	zl := logging.New(os.Getenv("SENTINEL_LOG_LEVEL"))

	app, err := server.Build(cfg, zl)
	if err != nil {
		zl.Fatal().Err(err).Msg("build app")
	}

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	zl.Info().Str("addr", addr).Str("store", cfg.Store.Kind).Bool("sim", cfg.Sim.Enabled).Msg("sentinel api starting")

	go func() {
		if err := app.Fiber.Listen(addr); err != nil {
			zl.Fatal().Err(err).Msg("listen")
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	zl.Info().Msg("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = app.Fiber.ShutdownWithContext(shutdownCtx)
	for _, fn := range app.Cleanups {
		fn()
	}
}
