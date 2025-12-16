package config

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Config holds all application configuration
type Config struct {
	// Data Source
	DataPath string

	// ClickHouse
	ClickHouse ClickHouseConfig

	// Redis
	Redis RedisConfig

	// MinIO
	MinIO MinIOConfig

	// Qdrant (Phase 2)
	Qdrant QdrantConfig

	// API Server
	API APIConfig

	// Worker Settings
	Worker WorkerConfig

	// Logging
	Log LogConfig

	// Metrics
	Metrics MetricsConfig
}

type ClickHouseConfig struct {
	Host     string
	Port     int
	Database string
	User     string
	Password string
}

type RedisConfig struct {
	Host                string
	Port                int
	Password            string
	DB                  int
	BloomFilterName     string
	BloomFilterErrorRate float64
	BloomFilterCapacity int64
}

type MinIOConfig struct {
	Endpoint  string
	AccessKey string
	SecretKey string
	Bucket    string
	UseSSL    bool
}

type QdrantConfig struct {
	Host       string
	GRPCPort   int
	RESTPort   int
	Collection string
}

type APIConfig struct {
	Host   string
	Port   int
	APIKey string
}

type WorkerConfig struct {
	Count          int
	BatchSize      int
	FileExtensions []string
}

type LogConfig struct {
	Level  string
	Format string
	File   string
}

type MetricsConfig struct {
	Enabled bool
	Port    int
}

// Load reads configuration from environment variables
func Load() (*Config, error) {
	// Load .env file if it exists (ignore error if not found)
	_ = godotenv.Load()

	cfg := &Config{
		DataPath: getEnv("DATA_PATH", "/data"),

		ClickHouse: ClickHouseConfig{
			Host:     getEnv("CLICKHOUSE_HOST", "localhost"),
			Port:     getEnvInt("CLICKHOUSE_PORT", 9000),
			Database: getEnv("CLICKHOUSE_DATABASE", "threat_intel"),
			User:     getEnv("CLICKHOUSE_USER", "default"),
			Password: getEnv("CLICKHOUSE_PASSWORD", ""),
		},

		Redis: RedisConfig{
			Host:                getEnv("REDIS_HOST", "localhost"),
			Port:                getEnvInt("REDIS_PORT", 6379),
			Password:            getEnv("REDIS_PASSWORD", ""),
			DB:                  getEnvInt("REDIS_DB", 0),
			BloomFilterName:     getEnv("BLOOM_FILTER_NAME", "ioc_bloom"),
			BloomFilterErrorRate: getEnvFloat("BLOOM_FILTER_ERROR_RATE", 0.001),
			BloomFilterCapacity: getEnvInt64("BLOOM_FILTER_CAPACITY", 10000000),
		},

		MinIO: MinIOConfig{
			Endpoint:  getEnv("MINIO_ENDPOINT", "localhost:9002"),
			AccessKey: getEnv("MINIO_ACCESS_KEY", "admin"),
			SecretKey: getEnv("MINIO_SECRET_KEY", "SuperSecretPassword123"),
			Bucket:    getEnv("MINIO_BUCKET", "misc-data"),
			UseSSL:    getEnvBool("MINIO_USE_SSL", false),
		},

		Qdrant: QdrantConfig{
			Host:       getEnv("QDRANT_HOST", "localhost"),
			GRPCPort:   getEnvInt("QDRANT_GRPC_PORT", 6334),
			RESTPort:   getEnvInt("QDRANT_REST_PORT", 6333),
			Collection: getEnv("QDRANT_COLLECTION", "threat_vectors"),
		},

		API: APIConfig{
			Host:   getEnv("API_HOST", "0.0.0.0"),
			Port:   getEnvInt("API_PORT", 8080),
			APIKey: getEnv("API_KEY", ""),
		},

		Worker: WorkerConfig{
			Count:          getEnvInt("WORKER_COUNT", 50),
			BatchSize:      getEnvInt("BATCH_SIZE", 1000),
			FileExtensions: getEnvSlice("FILE_EXTENSIONS", []string{".txt", ".log", ".json", ".csv", ".xml", ".html", ".md"}),
		},

		Log: LogConfig{
			Level:  getEnv("LOG_LEVEL", "info"),
			Format: getEnv("LOG_FORMAT", "json"),
			File:   getEnv("LOG_FILE", ""),
		},

		Metrics: MetricsConfig{
			Enabled: getEnvBool("METRICS_ENABLED", true),
			Port:    getEnvInt("METRICS_PORT", 9090),
		},
	}

	// Initialize logger based on config
	initLogger(cfg.Log)

	return cfg, nil
}

// initLogger sets up zerolog based on configuration
func initLogger(cfg LogConfig) {
	// Set log level
	level, err := zerolog.ParseLevel(cfg.Level)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)

	// Set output format
	if cfg.Format == "console" {
		log.Logger = log.Output(zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339,
		})
	}

	// Set log file if specified
	if cfg.File != "" {
		file, err := os.OpenFile(cfg.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err == nil {
			log.Logger = log.Output(file)
		}
	}
}

// Helper functions for reading environment variables

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

func getEnvInt64(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.ParseInt(value, 10, 64); err == nil {
			return intVal
		}
	}
	return defaultValue
}

func getEnvFloat(key string, defaultValue float64) float64 {
	if value := os.Getenv(key); value != "" {
		if floatVal, err := strconv.ParseFloat(value, 64); err == nil {
			return floatVal
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolVal, err := strconv.ParseBool(value); err == nil {
			return boolVal
		}
	}
	return defaultValue
}

func getEnvSlice(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		parts := strings.Split(value, ",")
		result := make([]string, 0, len(parts))
		for _, p := range parts {
			trimmed := strings.TrimSpace(p)
			if trimmed != "" {
				result = append(result, trimmed)
			}
		}
		return result
	}
	return defaultValue
}
