package store

import (
	"context"

	"github.com/i5dr0id/sentinel-api/internal/alerts"
	"github.com/i5dr0id/sentinel-api/internal/config"
	"github.com/rs/zerolog"
)

func NewAlertsStore(ctx context.Context, cfg *config.Config, log *zerolog.Logger) (alerts.Store, func(), error) {
	if cfg.Store.Kind == "postgres" {
		ps, err := NewPostgres(ctx, cfg.Store.DatabaseURL, log)
		if err != nil {
			return nil, nil, err
		}
		return ps, ps.Close, nil
	}
	return NewMemory(), func() {}, nil
}
