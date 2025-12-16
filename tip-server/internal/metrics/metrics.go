package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds all Prometheus metrics for the application
type Metrics struct {
	// Ingestor metrics
	FilesProcessed   *prometheus.CounterVec
	FilesSkipped     prometheus.Counter
	FilesFailed      prometheus.Counter
	IOCsExtracted    *prometheus.CounterVec
	BytesProcessed   prometheus.Counter
	ProcessingTime   *prometheus.HistogramVec
	ActiveWorkers    prometheus.Gauge
	BatchInsertTime  prometheus.Histogram
	BatchInsertSize  prometheus.Histogram

	// API metrics
	APIRequests      *prometheus.CounterVec
	APILatency       *prometheus.HistogramVec
	BloomFilterHits  prometheus.Counter
	BloomFilterMisses prometheus.Counter
	ClickHouseQueries *prometheus.CounterVec
	ClickHouseLatency prometheus.Histogram

	// System metrics
	DBConnections    *prometheus.GaugeVec
	BloomFilterSize  prometheus.Gauge
	BloomFilterItems prometheus.Gauge
}

// NewMetrics creates and registers all Prometheus metrics
func NewMetrics() *Metrics {
	m := &Metrics{
		// ========== Ingestor Metrics ==========
		FilesProcessed: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "tip_files_processed_total",
				Help: "Total number of files processed by status",
			},
			[]string{"status"}, // infected, clean, misc, failed
		),

		FilesSkipped: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "tip_files_skipped_total",
				Help: "Total number of files skipped (unchanged)",
			},
		),

		FilesFailed: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "tip_files_failed_total",
				Help: "Total number of files that failed processing",
			},
		),

		IOCsExtracted: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "tip_iocs_extracted_total",
				Help: "Total number of IOCs extracted by type",
			},
			[]string{"type"}, // ipv4, ipv6, md5, sha1, sha256, domain, url, email
		),

		BytesProcessed: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "tip_bytes_processed_total",
				Help: "Total bytes of file content processed",
			},
		),

		ProcessingTime: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "tip_file_processing_seconds",
				Help:    "Time spent processing individual files",
				Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10},
			},
			[]string{"status"},
		),

		ActiveWorkers: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "tip_active_workers",
				Help: "Number of currently active worker goroutines",
			},
		),

		BatchInsertTime: promauto.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "tip_batch_insert_seconds",
				Help:    "Time spent on batch inserts to ClickHouse",
				Buckets: []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
			},
		),

		BatchInsertSize: promauto.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "tip_batch_insert_size",
				Help:    "Number of IOCs in each batch insert",
				Buckets: []float64{10, 50, 100, 250, 500, 1000, 2500, 5000},
			},
		),

		// ========== API Metrics ==========
		APIRequests: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "tip_api_requests_total",
				Help: "Total number of API requests by endpoint and status",
			},
			[]string{"endpoint", "method", "status"},
		),

		APILatency: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "tip_api_latency_seconds",
				Help:    "API request latency by endpoint",
				Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1},
			},
			[]string{"endpoint", "method"},
		),

		BloomFilterHits: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "tip_bloom_filter_hits_total",
				Help: "Total number of Bloom filter hits (potential matches)",
			},
		),

		BloomFilterMisses: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "tip_bloom_filter_misses_total",
				Help: "Total number of Bloom filter misses (definite non-matches)",
			},
		),

		ClickHouseQueries: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "tip_clickhouse_queries_total",
				Help: "Total number of ClickHouse queries by type",
			},
			[]string{"query_type"}, // select, insert, batch_insert
		),

		ClickHouseLatency: promauto.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "tip_clickhouse_query_seconds",
				Help:    "ClickHouse query latency",
				Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5},
			},
		),

		// ========== System Metrics ==========
		DBConnections: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "tip_db_connections",
				Help: "Number of database connections by type",
			},
			[]string{"database"}, // clickhouse, redis, minio
		),

		BloomFilterSize: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "tip_bloom_filter_size_bytes",
				Help: "Size of the Bloom filter in bytes",
			},
		),

		BloomFilterItems: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "tip_bloom_filter_items",
				Help: "Number of items in the Bloom filter",
			},
		),
	}

	return m
}

// Global metrics instance
var globalMetrics *Metrics

// GetMetrics returns the global metrics instance
func GetMetrics() *Metrics {
	if globalMetrics == nil {
		globalMetrics = NewMetrics()
	}
	return globalMetrics
}

// ========== Helper Methods ==========

// RecordFileProcessed records a processed file
func (m *Metrics) RecordFileProcessed(status string, durationSeconds float64) {
	m.FilesProcessed.WithLabelValues(status).Inc()
	m.ProcessingTime.WithLabelValues(status).Observe(durationSeconds)
}

// RecordIOCsExtracted records extracted IOCs by type
func (m *Metrics) RecordIOCsExtracted(iocType string, count int) {
	m.IOCsExtracted.WithLabelValues(iocType).Add(float64(count))
}

// RecordAPIRequest records an API request
func (m *Metrics) RecordAPIRequest(endpoint, method string, statusCode int, durationSeconds float64) {
	status := "success"
	if statusCode >= 400 {
		status = "error"
	}
	m.APIRequests.WithLabelValues(endpoint, method, status).Inc()
	m.APILatency.WithLabelValues(endpoint, method).Observe(durationSeconds)
}

// RecordBloomFilterCheck records a Bloom filter check result
func (m *Metrics) RecordBloomFilterCheck(hit bool) {
	if hit {
		m.BloomFilterHits.Inc()
	} else {
		m.BloomFilterMisses.Inc()
	}
}

// RecordBatchInsert records a batch insert operation
func (m *Metrics) RecordBatchInsert(size int, durationSeconds float64) {
	m.BatchInsertSize.Observe(float64(size))
	m.BatchInsertTime.Observe(durationSeconds)
	m.ClickHouseQueries.WithLabelValues("batch_insert").Inc()
}

// UpdateBloomFilterStats updates Bloom filter statistics
func (m *Metrics) UpdateBloomFilterStats(sizeBytes, items int64) {
	m.BloomFilterSize.Set(float64(sizeBytes))
	m.BloomFilterItems.Set(float64(items))
}
