package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"tip-server/internal/config"
	"tip-server/internal/db"
	"tip-server/internal/metrics"
	"tip-server/internal/middleware"
	"tip-server/internal/models"
)

// Server holds all dependencies for the API server
type Server struct {
	cfg     *config.Config
	app     *fiber.App
	ch      *db.ClickHouseClient
	redis   *db.RedisClient
	minio   *db.MinIOClient
	qdrant  *db.QdrantClient
	metrics *metrics.Metrics
}

func main() {
	// Initialize logger
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339})

	log.Info().Msg("Starting Threat Intelligence Platform - API Server")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load configuration")
	}

	// Create server
	server, err := NewServer(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create server")
	}
	defer server.Close()

	// Setup routes
	server.SetupRoutes()

	// Start metrics server (separate port)
	if cfg.Metrics.Enabled {
		go server.StartMetricsServer()
	}

	// Handle graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		log.Info().Msg("Shutting down server...")
		if err := server.app.Shutdown(); err != nil {
			log.Error().Err(err).Msg("Error during shutdown")
		}
	}()

	// Start server
	addr := fmt.Sprintf("%s:%d", cfg.API.Host, cfg.API.Port)
	log.Info().Str("addr", addr).Msg("Starting API server")

	if err := server.app.Listen(addr); err != nil {
		log.Fatal().Err(err).Msg("Server failed")
	}
}

// NewServer creates a new API server
func NewServer(cfg *config.Config) (*Server, error) {
	// Connect to ClickHouse
	ch, err := db.NewClickHouseClient(cfg.ClickHouse)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to ClickHouse: %w", err)
	}

	// Connect to Redis
	redis, err := db.NewRedisClient(cfg.Redis)
	if err != nil {
		ch.Close()
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	// Connect to MinIO
	minio, err := db.NewMinIOClient(cfg.MinIO)
	if err != nil {
		ch.Close()
		redis.Close()
		return nil, fmt.Errorf("failed to connect to MinIO: %w", err)
	}

	// Connect to Qdrant (optional, Phase 2)
	qdrant, _ := db.NewQdrantClient(cfg.Qdrant)

	// Create Fiber app
	app := fiber.New(fiber.Config{
		AppName:               "TIP API",
		ReadTimeout:           30 * time.Second,
		WriteTimeout:          30 * time.Second,
		IdleTimeout:           120 * time.Second,
		DisableStartupMessage: false,
		ErrorHandler:          errorHandler,
	})

	return &Server{
		cfg:     cfg,
		app:     app,
		ch:      ch,
		redis:   redis,
		minio:   minio,
		qdrant:  qdrant,
		metrics: metrics.GetMetrics(),
	}, nil
}

// Close closes all connections
func (s *Server) Close() {
	s.ch.Close()
	s.redis.Close()
	if s.qdrant != nil {
		s.qdrant.Close()
	}
}

// SetupRoutes configures all API routes
func (s *Server) SetupRoutes() {
	// Global middleware
	s.app.Use(middleware.RecoverMiddleware())
	s.app.Use(middleware.CORSMiddleware())
	s.app.Use(middleware.RequestLogger())
	s.app.Use(compress.New())

	// Authentication middleware (skip health and metrics)
	authMiddleware := middleware.NewAuthMiddleware(middleware.AuthConfig{
		APIKey:     s.cfg.API.APIKey,
		Redis:      s.redis,
		RateLimit:  1000, // requests per minute
		RateWindow: time.Minute,
		SkipPaths:  []string{"/health", "/readyz", "/metrics"},
	})

	// Public endpoints
	s.app.Get("/health", s.healthHandler)
	s.app.Get("/readyz", s.readinessHandler)

	// Protected endpoints
	api := s.app.Group("/", authMiddleware)
	api.Post("/check", s.checkHandler)
	api.Get("/context/:file_id", s.contextHandler)
	api.Get("/stats", s.statsHandler)

	// Phase 2 (stub)
	api.Post("/search/fuzzy", s.fuzzySearchHandler)
}

// StartMetricsServer starts the Prometheus metrics server
func (s *Server) StartMetricsServer() {
	addr := fmt.Sprintf(":%d", s.cfg.Metrics.Port)
	log.Info().Str("addr", addr).Msg("Starting metrics server")

	http.Handle("/metrics", promhttp.Handler())
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Error().Err(err).Msg("Metrics server failed")
	}
}

// ========== Handlers ==========

// healthHandler returns service health status
func (s *Server) healthHandler(c *fiber.Ctx) error {
	return c.JSON(models.HealthResponse{
		Status:    "healthy",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Components: map[string]string{
			"api": "up",
		},
	})
}

// readinessHandler checks if all dependencies are ready
func (s *Server) readinessHandler(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	components := make(map[string]string)
	allHealthy := true

	// Check ClickHouse
	if err := s.ch.Ping(ctx); err != nil {
		components["clickhouse"] = "down: " + err.Error()
		allHealthy = false
	} else {
		components["clickhouse"] = "up"
	}

	// Check Redis
	if err := s.redis.Ping(ctx); err != nil {
		components["redis"] = "down: " + err.Error()
		allHealthy = false
	} else {
		components["redis"] = "up"
	}

	// Check Qdrant (optional)
	if s.qdrant != nil && s.qdrant.IsInitialized() {
		components["qdrant"] = "up"
	} else {
		components["qdrant"] = "not configured (Phase 2)"
	}

	status := "ready"
	statusCode := fiber.StatusOK
	if !allHealthy {
		status = "not ready"
		statusCode = fiber.StatusServiceUnavailable
	}

	return c.Status(statusCode).JSON(models.HealthResponse{
		Status:     status,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Components: components,
	})
}

// checkHandler handles IOC lookup requests
func (s *Server) checkHandler(c *fiber.Ctx) error {
	startTime := time.Now()

	// Parse request
	var req models.CheckRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(models.ErrorResponse{
			Error: "Invalid request body",
			Code:  fiber.StatusBadRequest,
		})
	}

	if len(req.IOCs) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(models.ErrorResponse{
			Error: "No IOCs provided",
			Code:  fiber.StatusBadRequest,
		})
	}

	if len(req.IOCs) > 1000 {
		return c.Status(fiber.StatusBadRequest).JSON(models.ErrorResponse{
			Error:   "Too many IOCs",
			Code:    fiber.StatusBadRequest,
			Details: "Maximum 1000 IOCs per request",
		})
	}

	ctx := context.Background()

	// Step 1: Bloom filter check
	bloomResults, err := s.redis.BFMExists(ctx, req.IOCs)
	if err != nil {
		log.Error().Err(err).Msg("Bloom filter check failed")
		// Continue without bloom filter on error
		bloomResults = make([]bool, len(req.IOCs))
		for i := range bloomResults {
			bloomResults[i] = true // Assume all might exist
		}
	}

	// Filter to potential hits
	var potentialHits []string
	hitIndices := make(map[string]int) // Map IOC to original index

	for i, ioc := range req.IOCs {
		if bloomResults[i] {
			potentialHits = append(potentialHits, ioc)
			hitIndices[ioc] = i
			s.metrics.RecordBloomFilterCheck(true)
		} else {
			s.metrics.RecordBloomFilterCheck(false)
		}
	}

	// Step 2: Query ClickHouse for potential hits
	var foundIOCs []models.IOC
	if len(potentialHits) > 0 {
		foundIOCs, err = s.ch.QueryIOCs(ctx, potentialHits)
		if err != nil {
			log.Error().Err(err).Msg("ClickHouse query failed")
		}
	}

	// Build results
	foundMap := make(map[string]models.IOC)
	for _, ioc := range foundIOCs {
		foundMap[ioc.Value] = ioc
	}

	results := make([]models.IOCResult, len(req.IOCs))
	foundCount := 0

	for i, ioc := range req.IOCs {
		result := models.IOCResult{
			IOC:   ioc,
			Found: false,
		}

		if found, ok := foundMap[ioc]; ok {
			result.Found = true
			result.Type = found.Type
			result.SourceFileID = found.SourceFileID
			result.MalwareFamily = found.MalwareFamily
			result.Confidence = found.Confidence
			result.FirstSeen = found.FirstSeen.Format(time.RFC3339)
			foundCount++
		}

		results[i] = result
	}

	queryTime := time.Since(startTime)
	s.metrics.RecordAPIRequest("/check", "POST", fiber.StatusOK, queryTime.Seconds())

	return c.JSON(models.CheckResponse{
		Results:   results,
		Total:     len(req.IOCs),
		Found:     foundCount,
		NotFound:  len(req.IOCs) - foundCount,
		QueryTime: queryTime.String(),
	})
}

// contextHandler streams file content from MinIO
func (s *Server) contextHandler(c *fiber.Ctx) error {
	fileID := c.Params("file_id")
	if fileID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(models.ErrorResponse{
			Error: "Missing file_id",
			Code:  fiber.StatusBadRequest,
		})
	}

	ctx := context.Background()

	// Get file metadata from ClickHouse
	meta, err := s.ch.GetFileMetadata(ctx, fileID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(models.ErrorResponse{
			Error:   "File not found",
			Code:    fiber.StatusNotFound,
			Details: fileID,
		})
	}

	// Check if file is in MinIO
	minioKey := meta.MinIOKey
	if minioKey == "" {
		minioKey = fileID // Fallback to file_id as key
	}

	// Get object from MinIO
	obj, err := s.minio.GetObject(ctx, minioKey)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(models.ErrorResponse{
			Error:   "File content not available",
			Code:    fiber.StatusNotFound,
			Details: "File may not have been stored in object storage",
		})
	}
	defer obj.Close()

	// Get object info for headers
	info, err := obj.Stat()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(models.ErrorResponse{
			Error: "Failed to get file info",
			Code:  fiber.StatusInternalServerError,
		})
	}

	// Set headers
	c.Set("Content-Type", info.ContentType)
	c.Set("Content-Length", strconv.FormatInt(info.Size, 10))
	c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", fileID))
	c.Set("X-File-ID", fileID)
	c.Set("X-Original-Path", meta.FilePath)

	// Stream content
	_, err = io.Copy(c.Response().BodyWriter(), obj)
	if err != nil {
		log.Error().Err(err).Str("file_id", fileID).Msg("Failed to stream file")
	}

	s.metrics.RecordAPIRequest("/context", "GET", fiber.StatusOK, 0)
	return nil
}

// statsHandler returns system statistics
func (s *Server) statsHandler(c *fiber.Ctx) error {
	ctx := context.Background()

	// Get IOC stats
	iocStats, err := s.ch.GetIOCStats(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get IOC stats")
	}

	// Get file stats
	fileStats, err := s.ch.GetFileStats(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get file stats")
	}

	// Get Bloom filter info
	var bloomInfo map[string]interface{}
	if info, err := s.redis.BFInfo(ctx); err == nil {
		bloomInfo = map[string]interface{}{
			"capacity":       info.Capacity,
			"size":           info.Size,
			"items_inserted": info.ItemsInserted,
			"expansion_rate": info.ExpansionRate,
		}

		s.metrics.UpdateBloomFilterStats(info.Size, info.ItemsInserted)
	}

	return c.JSON(fiber.Map{
		"ioc_stats":         iocStats,
		"file_stats":        fileStats,
		"bloom_filter_info": bloomInfo,
		"timestamp":         time.Now().UTC().Format(time.RFC3339),
	})
}

// fuzzySearchHandler handles fuzzy/semantic search (Phase 2 stub)
func (s *Server) fuzzySearchHandler(c *fiber.Ctx) error {
	return c.Status(fiber.StatusNotImplemented).JSON(models.ErrorResponse{
		Error:   "Not implemented",
		Code:    fiber.StatusNotImplemented,
		Details: "Fuzzy search will be available in Phase 2 with Qdrant integration",
	})
}

// errorHandler handles Fiber errors
func errorHandler(c *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError
	message := "Internal server error"

	if e, ok := err.(*fiber.Error); ok {
		code = e.Code
		message = e.Message
	}

	log.Error().
		Err(err).
		Int("code", code).
		Str("path", c.Path()).
		Msg("Request error")

	return c.Status(code).JSON(models.ErrorResponse{
		Error: message,
		Code:  code,
	})
}
