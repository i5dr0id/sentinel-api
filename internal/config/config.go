package config

import (
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Server      ServerConfig `mapstructure:"server"`
	Store       StoreConfig  `mapstructure:"store"`
	Sim         SimConfig    `mapstructure:"sim"`
	Geo         GeoConfig    `mapstructure:"geo"`
	Tail        TailConfig   `mapstructure:"tail"`
	Assets      []string     `mapstructure:"assets"`
	IngestToken string       `mapstructure:"ingest_token"`
}

type TailConfig struct {
	Paths []string `mapstructure:"paths"`
	Asset string   `mapstructure:"asset"`
}

type ServerConfig struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
}

type StoreConfig struct {
	Kind        string `mapstructure:"kind"`
	DatabaseURL string `mapstructure:"database_url"`
}

type SimConfig struct {
	Enabled bool          `mapstructure:"enabled"`
	Rate    float64       `mapstructure:"rate"`
	Jitter  time.Duration `mapstructure:"jitter"`
}

type GeoConfig struct {
	MaxmindDBPath string `mapstructure:"maxmind_db_path"`
}

func Default() *Config {
	return &Config{
		Server: ServerConfig{Host: "0.0.0.0", Port: 3000},
		Store:  StoreConfig{Kind: "memory"},
		Sim:    SimConfig{Enabled: true, Rate: 18, Jitter: 150 * time.Millisecond},
		Geo:    GeoConfig{},
		Assets: []string{"api-gw-01", "api-gw-02", "www-01", "auth-svc-01", "Internal-DB-01"},
	}
}

func Load() (*Config, error) {
	cfg := Default()

	v := viper.New()
	v.SetEnvPrefix("SENTINEL")
	v.AutomaticEnv()
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath("./configs")
	v.AddConfigPath("../configs")

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}

	v.SetDefault("server.host", cfg.Server.Host)
	v.SetDefault("server.port", cfg.Server.Port)
	v.SetDefault("store.kind", cfg.Store.Kind)
	v.SetDefault("store.database_url", "")
	v.SetDefault("sim.enabled", cfg.Sim.Enabled)
	v.SetDefault("sim.rate", cfg.Sim.Rate)
	v.SetDefault("sim.jitter", cfg.Sim.Jitter.String())
	v.SetDefault("geo.maxmind_db_path", "")
	v.SetDefault("assets", cfg.Assets)
	v.SetDefault("ingest_token", "")
	v.SetDefault("tail.paths", []string{})
	v.SetDefault("tail.asset", "api-gw-01")

	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	if cfg.Store.Kind == "" {
		cfg.Store.Kind = "memory"
	}
	if cfg.Store.DatabaseURL == "" {
		cfg.Store.DatabaseURL = v.GetString("store.database_url")
	}
	return cfg, nil
}
