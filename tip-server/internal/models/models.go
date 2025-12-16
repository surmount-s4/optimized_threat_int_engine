package models

import (
	"time"
)

// IOCType represents the type of Indicator of Compromise
type IOCType string

const (
	IOCTypeIPv4   IOCType = "ipv4"
	IOCTypeIPv6   IOCType = "ipv6"
	IOCTypeDomain IOCType = "domain"
	IOCTypeURL    IOCType = "url"
	IOCTypeMD5    IOCType = "md5"
	IOCTypeSHA1   IOCType = "sha1"
	IOCTypeSHA256 IOCType = "sha256"
	IOCTypeEmail  IOCType = "email"
)

// AllIOCTypes returns all supported IOC types
func AllIOCTypes() []IOCType {
	return []IOCType{
		IOCTypeIPv4,
		IOCTypeIPv6,
		IOCTypeDomain,
		IOCTypeURL,
		IOCTypeMD5,
		IOCTypeSHA1,
		IOCTypeSHA256,
		IOCTypeEmail,
	}
}

// ScanStatus represents the processing status of a file
type ScanStatus string

const (
	ScanStatusPending  ScanStatus = "pending"
	ScanStatusClean    ScanStatus = "clean"
	ScanStatusInfected ScanStatus = "infected"
	ScanStatusMisc     ScanStatus = "misc"
	ScanStatusFailed   ScanStatus = "failed"
)

// IOC represents an Indicator of Compromise
type IOC struct {
	Value         string    `json:"value" ch:"ioc_value"`
	Type          IOCType   `json:"type" ch:"ioc_type"`
	SourceFileID  string    `json:"source_file_id" ch:"source_file_id"`
	MalwareFamily string    `json:"malware_family,omitempty" ch:"malware_family"`
	Confidence    uint8     `json:"confidence" ch:"confidence"`
	FirstSeen     time.Time `json:"first_seen" ch:"first_seen"`
	LastSeen      time.Time `json:"last_seen" ch:"last_seen"`
	HitCount      uint32    `json:"hit_count" ch:"hit_count"`
	VectorID      *uint64   `json:"vector_id,omitempty" ch:"vector_id"` // Phase 2: Qdrant integration
	Tags          []string  `json:"tags,omitempty" ch:"tags"`
}

// FileMetadata represents information about a processed file
type FileMetadata struct {
	FileID       string     `json:"file_id" ch:"file_id"`
	FilePath     string     `json:"file_path" ch:"file_path"`
	FileSize     uint64     `json:"file_size" ch:"file_size"`
	LastModified time.Time  `json:"last_modified" ch:"last_modified"`
	ScanStatus   ScanStatus `json:"scan_status" ch:"scan_status"`
	IOCCount     uint32     `json:"ioc_count" ch:"ioc_count"`
	MinIOKey     string     `json:"minio_key,omitempty" ch:"minio_key"`
	ErrorMessage string     `json:"error_message,omitempty" ch:"error_message"`
	ProcessedAt  time.Time  `json:"processed_at" ch:"processed_at"`
	UpdatedAt    time.Time  `json:"updated_at" ch:"updated_at"`
}

// APIKey represents an API key for authentication
type APIKey struct {
	KeyHash     string    `json:"key_hash" ch:"key_hash"`
	KeyName     string    `json:"key_name" ch:"key_name"`
	Permissions []string  `json:"permissions" ch:"permissions"`
	RateLimit   uint32    `json:"rate_limit" ch:"rate_limit"`
	IsActive    bool      `json:"is_active" ch:"is_active"`
	CreatedAt   time.Time `json:"created_at" ch:"created_at"`
	LastUsed    time.Time `json:"last_used" ch:"last_used"`
}

// ========== API Request/Response Models ==========

// CheckRequest represents a request to check IOCs
type CheckRequest struct {
	IOCs []string `json:"iocs" validate:"required,min=1,max=1000"`
}

// CheckResponse represents the response from IOC check
type CheckResponse struct {
	Results   []IOCResult `json:"results"`
	Total     int         `json:"total"`
	Found     int         `json:"found"`
	NotFound  int         `json:"not_found"`
	QueryTime string      `json:"query_time"`
}

// IOCResult represents a single IOC lookup result
type IOCResult struct {
	IOC           string  `json:"ioc"`
	Found         bool    `json:"found"`
	Type          IOCType `json:"type,omitempty"`
	SourceFileID  string  `json:"source_file_id,omitempty"`
	MalwareFamily string  `json:"malware_family,omitempty"`
	Confidence    uint8   `json:"confidence,omitempty"`
	FirstSeen     string  `json:"first_seen,omitempty"`
}

// ContextResponse represents file context response
type ContextResponse struct {
	FileID       string `json:"file_id"`
	FilePath     string `json:"file_path"`
	FileSize     uint64 `json:"file_size"`
	LastModified string `json:"last_modified"`
	IOCCount     uint32 `json:"ioc_count"`
	ContentType  string `json:"content_type"`
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status     string            `json:"status"`
	Timestamp  string            `json:"timestamp"`
	Components map[string]string `json:"components"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    int    `json:"code"`
	Details string `json:"details,omitempty"`
}

// ========== Ingestor Models ==========

// FileJob represents a file to be processed by the worker pool
type FileJob struct {
	FilePath     string
	FileSize     int64
	LastModified time.Time
}

// ProcessResult represents the result of processing a file
type ProcessResult struct {
	FileID     string
	FilePath   string
	Status     ScanStatus
	IOCCount   int
	IOCs       map[IOCType][]string
	Error      error
	Duration   time.Duration
}

// BatchInsert represents a batch of IOCs to insert
type BatchInsert struct {
	IOCs     []IOC
	FileID   string
	FilePath string
}

// ========== Statistics Models ==========

// IngestorStats represents ingestor statistics
type IngestorStats struct {
	FilesProcessed   int64         `json:"files_processed"`
	FilesSkipped     int64         `json:"files_skipped"`
	FilesFailed      int64         `json:"files_failed"`
	IOCsExtracted    int64         `json:"iocs_extracted"`
	BytesProcessed   int64         `json:"bytes_processed"`
	Duration         time.Duration `json:"duration"`
	IOCsByType       map[IOCType]int64 `json:"iocs_by_type"`
}

// APIStats represents API statistics
type APIStats struct {
	TotalRequests   int64 `json:"total_requests"`
	BloomHits       int64 `json:"bloom_hits"`
	BloomMisses     int64 `json:"bloom_misses"`
	ClickHouseHits  int64 `json:"clickhouse_hits"`
	AverageLatency  int64 `json:"average_latency_ms"`
}
