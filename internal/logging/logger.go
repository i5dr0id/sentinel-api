package logging

import (
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

func New(level string) *zerolog.Logger {
	lvl := zerolog.InfoLevel
	switch strings.ToLower(level) {
	case "debug":
		lvl = zerolog.DebugLevel
	case "warn":
		lvl = zerolog.WarnLevel
	case "error":
		lvl = zerolog.ErrorLevel
	case "trace":
		lvl = zerolog.TraceLevel
	}
	zerolog.TimeFieldFormat = time.RFC3339
	zl := zerolog.New(os.Stderr).Level(lvl).With().Timestamp().Logger()
	return &zl
}
