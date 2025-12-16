package main

import (
	"context"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"tip-server/internal/config"
	"tip-server/internal/db"
	"tip-server/internal/extractor"
	"tip-server/internal/metrics"
	"tip-server/internal/models"
)

// Ingestor orchestrates the file crawling and IOC extraction
type Ingestor struct {
	cfg       *config.Config
	ch        *db.ClickHouseClient
	redis     *db.RedisClient
	minio     *db.MinIOClient
	extractor *extractor.Extractor
	metrics   *metrics.Metrics

	// Worker pool
	jobs    chan models.FileJob
	results chan models.ProcessResult
	wg      sync.WaitGroup

	// Statistics
	stats IngestorStats

	// Control
	ctx    context.Context
	cancel context.CancelFunc
}

// IngestorStats tracks ingestion statistics
type IngestorStats struct {
	FilesProcessed int64
	FilesSkipped   int64
	FilesFailed    int64
	IOCsExtracted  int64
	BytesProcessed int64
	StartTime      time.Time
}

func main() {
	// Initialize logger
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339})

	log.Info().Msg("Starting Threat Intelligence Platform - Ingestor")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load configuration")
	}

	// Create ingestor
	ingestor, err := NewIngestor(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create ingestor")
	}
	defer ingestor.Close()

	// Handle graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Info().Msg("Received shutdown signal, gracefully stopping...")
		cancel()
	}()

	// Run ingestion
	if err := ingestor.Run(ctx); err != nil {
		log.Error().Err(err).Msg("Ingestion failed")
		os.Exit(1)
	}

	// Print final statistics
	ingestor.PrintStats()
}

// NewIngestor creates a new ingestor instance
func NewIngestor(cfg *config.Config) (*Ingestor, error) {
	// Connect to ClickHouse
	ch, err := db.NewClickHouseClient(cfg.ClickHouse)
	if err != nil {
		return nil, err
	}

	// Connect to Redis
	redis, err := db.NewRedisClient(cfg.Redis)
	if err != nil {
		ch.Close()
		return nil, err
	}

	// Connect to MinIO
	minio, err := db.NewMinIOClient(cfg.MinIO)
	if err != nil {
		ch.Close()
		redis.Close()
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Ingestor{
		cfg:       cfg,
		ch:        ch,
		redis:     redis,
		minio:     minio,
		extractor: extractor.NewExtractor(),
		metrics:   metrics.GetMetrics(),
		jobs:      make(chan models.FileJob, cfg.Worker.Count*2),
		results:   make(chan models.ProcessResult, cfg.Worker.Count*2),
		ctx:       ctx,
		cancel:    cancel,
		stats: IngestorStats{
			StartTime: time.Now(),
		},
	}, nil
}

// Close closes all connections
func (i *Ingestor) Close() {
	i.cancel()
	i.ch.Close()
	i.redis.Close()
}

// Run starts the ingestion process
func (i *Ingestor) Run(ctx context.Context) error {
	log.Info().
		Str("data_path", i.cfg.DataPath).
		Int("workers", i.cfg.Worker.Count).
		Int("batch_size", i.cfg.Worker.BatchSize).
		Msg("Starting ingestion")

	// Start result collector
	var collectorWg sync.WaitGroup
	collectorWg.Add(1)
	go i.resultCollector(&collectorWg)

	// Start workers
	for w := 0; w < i.cfg.Worker.Count; w++ {
		i.wg.Add(1)
		go i.worker(w)
	}

	// Start batch processor
	batchChan := make(chan []models.IOC, 10)
	var batchWg sync.WaitGroup
	batchWg.Add(1)
	go i.batchProcessor(batchChan, &batchWg)

	// Crawl directory and enqueue jobs
	err := i.crawl(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Crawl error")
	}

	// Close jobs channel and wait for workers
	close(i.jobs)
	i.wg.Wait()

	// Close results channel and wait for collector
	close(i.results)
	collectorWg.Wait()

	// Close batch channel
	close(batchChan)
	batchWg.Wait()

	log.Info().Msg("Ingestion complete")
	return nil
}

// crawl walks the directory and enqueues files for processing
func (i *Ingestor) crawl(ctx context.Context) error {
	extensions := make(map[string]bool)
	for _, ext := range i.cfg.Worker.FileExtensions {
		extensions[strings.ToLower(ext)] = true
	}

	return filepath.WalkDir(i.cfg.DataPath, func(path string, d fs.DirEntry, err error) error {
		// Check for cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err != nil {
			log.Warn().Err(err).Str("path", path).Msg("Error accessing path")
			return nil // Continue walking
		}

		// Skip directories
		if d.IsDir() {
			return nil
		}

		// Check file extension
		ext := strings.ToLower(filepath.Ext(path))
		if len(extensions) > 0 && !extensions[ext] {
			return nil
		}

		// Get file info
		info, err := d.Info()
		if err != nil {
			log.Warn().Err(err).Str("path", path).Msg("Failed to get file info")
			return nil
		}

		// Enqueue job
		job := models.FileJob{
			FilePath:     path,
			FileSize:     info.Size(),
			LastModified: info.ModTime(),
		}

		select {
		case i.jobs <- job:
		case <-ctx.Done():
			return ctx.Err()
		}

		return nil
	})
}

// worker processes files from the jobs channel
func (i *Ingestor) worker(id int) {
	defer i.wg.Done()

	i.metrics.ActiveWorkers.Inc()
	defer i.metrics.ActiveWorkers.Dec()

	for job := range i.jobs {
		result := i.processFile(job)

		select {
		case i.results <- result:
		case <-i.ctx.Done():
			return
		}
	}
}

// processFile processes a single file
func (i *Ingestor) processFile(job models.FileJob) models.ProcessResult {
	startTime := time.Now()

	result := models.ProcessResult{
		FilePath: job.FilePath,
		FileID:   db.GenerateFileID(job.FilePath),
	}

	// Check if file has changed
	changed, err := i.ch.CheckFileChanged(i.ctx, result.FileID, job.LastModified)
	if err != nil {
		log.Debug().Err(err).Str("file", job.FilePath).Msg("Change detection query (new file)")
	}

	if !changed {
		result.Status = models.ScanStatusClean // Unchanged, skip
		atomic.AddInt64(&i.stats.FilesSkipped, 1)
		i.metrics.FilesSkipped.Inc()
		return result
	}

	// Read file content
	content, err := os.ReadFile(job.FilePath)
	if err != nil {
		result.Status = models.ScanStatusFailed
		result.Error = err
		atomic.AddInt64(&i.stats.FilesFailed, 1)
		i.metrics.FilesFailed.Inc()
		log.Warn().Err(err).Str("file", job.FilePath).Msg("Failed to read file")
		return result
	}

	atomic.AddInt64(&i.stats.BytesProcessed, int64(len(content)))
	i.metrics.BytesProcessed.Add(float64(len(content)))

	// Extract IOCs
	iocs, err := i.extractor.Scan(content)
	if err != nil {
		result.Status = models.ScanStatusFailed
		result.Error = err
		atomic.AddInt64(&i.stats.FilesFailed, 1)
		i.metrics.FilesFailed.Inc()
		return result
	}

	result.IOCs = iocs
	result.IOCCount = extractor.CountIOCs(iocs)
	result.Duration = time.Since(startTime)

	if result.IOCCount > 0 {
		result.Status = models.ScanStatusInfected
		atomic.AddInt64(&i.stats.IOCsExtracted, int64(result.IOCCount))

		// Record IOCs by type
		for iocType, values := range iocs {
			i.metrics.RecordIOCsExtracted(string(iocType), len(values))
		}

		// Add IOCs to Bloom filter
		for _, values := range iocs {
			if len(values) > 0 {
				if err := i.redis.BFMAdd(i.ctx, values); err != nil {
					log.Warn().Err(err).Msg("Failed to add IOCs to Bloom filter")
				}
			}
		}

		// Batch insert IOCs to ClickHouse
		iocList := extractor.FlattenIOCs(iocs, result.FileID)
		now := time.Now()
		for idx := range iocList {
			iocList[idx].FirstSeen = now
			iocList[idx].LastSeen = now
			iocList[idx].Confidence = 50
			iocList[idx].MalwareFamily = "Unknown"
		}

		if err := i.ch.BatchInsertIOCs(i.ctx, iocList); err != nil {
			log.Error().Err(err).Str("file", job.FilePath).Msg("Failed to insert IOCs")
		} else {
			i.metrics.RecordBatchInsert(len(iocList), time.Since(startTime).Seconds())
		}

	} else {
		result.Status = models.ScanStatusMisc

		// Upload to MinIO
		minioKey := result.FileID
		contentType := db.GetContentType(job.FilePath)
		_, err := i.minio.UploadBytes(i.ctx, minioKey, content, contentType)
		if err != nil {
			log.Warn().Err(err).Str("file", job.FilePath).Msg("Failed to upload to MinIO")
		}
	}

	// Update file registry
	meta := &models.FileMetadata{
		FileID:       result.FileID,
		FilePath:     job.FilePath,
		FileSize:     uint64(job.FileSize),
		LastModified: job.LastModified,
		ScanStatus:   result.Status,
		IOCCount:     uint32(result.IOCCount),
		ProcessedAt:  time.Now(),
	}

	if result.Status == models.ScanStatusMisc {
		meta.MinIOKey = result.FileID
	}

	if result.Error != nil {
		meta.ErrorMessage = result.Error.Error()
	}

	if err := i.ch.UpsertFileMetadata(i.ctx, meta); err != nil {
		log.Warn().Err(err).Str("file", job.FilePath).Msg("Failed to update file registry")
	}

	atomic.AddInt64(&i.stats.FilesProcessed, 1)
	i.metrics.RecordFileProcessed(string(result.Status), result.Duration.Seconds())

	return result
}

// resultCollector collects and logs results
func (i *Ingestor) resultCollector(wg *sync.WaitGroup) {
	defer wg.Done()

	logTicker := time.NewTicker(10 * time.Second)
	defer logTicker.Stop()

	for {
		select {
		case result, ok := <-i.results:
			if !ok {
				return
			}

			// Log significant results
			if result.IOCCount > 0 {
				log.Info().
					Str("file", result.FilePath).
					Str("status", string(result.Status)).
					Int("ioc_count", result.IOCCount).
					Dur("duration", result.Duration).
					Msg("Processed file with IOCs")
			}

		case <-logTicker.C:
			// Periodic status log
			log.Info().
				Int64("processed", atomic.LoadInt64(&i.stats.FilesProcessed)).
				Int64("skipped", atomic.LoadInt64(&i.stats.FilesSkipped)).
				Int64("failed", atomic.LoadInt64(&i.stats.FilesFailed)).
				Int64("iocs", atomic.LoadInt64(&i.stats.IOCsExtracted)).
				Int64("bytes", atomic.LoadInt64(&i.stats.BytesProcessed)).
				Msg("Ingestion progress")
		}
	}
}

// batchProcessor handles batch operations (currently unused, for future optimization)
func (i *Ingestor) batchProcessor(batches <-chan []models.IOC, wg *sync.WaitGroup) {
	defer wg.Done()

	for batch := range batches {
		if len(batch) == 0 {
			continue
		}

		startTime := time.Now()
		if err := i.ch.BatchInsertIOCs(i.ctx, batch); err != nil {
			log.Error().Err(err).Int("count", len(batch)).Msg("Batch insert failed")
		} else {
			i.metrics.RecordBatchInsert(len(batch), time.Since(startTime).Seconds())
		}
	}
}

// PrintStats prints final ingestion statistics
func (i *Ingestor) PrintStats() {
	duration := time.Since(i.stats.StartTime)

	log.Info().
		Int64("files_processed", i.stats.FilesProcessed).
		Int64("files_skipped", i.stats.FilesSkipped).
		Int64("files_failed", i.stats.FilesFailed).
		Int64("iocs_extracted", i.stats.IOCsExtracted).
		Int64("bytes_processed", i.stats.BytesProcessed).
		Dur("duration", duration).
		Float64("files_per_sec", float64(i.stats.FilesProcessed)/duration.Seconds()).
		Msg("Ingestion complete")
}
