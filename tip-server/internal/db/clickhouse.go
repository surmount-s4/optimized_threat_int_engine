package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/rs/zerolog/log"

	"tip-server/internal/config"
	"tip-server/internal/models"
)

// ClickHouseClient wraps the ClickHouse connection
type ClickHouseClient struct {
	conn driver.Conn
	cfg  config.ClickHouseConfig
}

// NewClickHouseClient creates a new ClickHouse client
func NewClickHouseClient(cfg config.ClickHouseConfig) (*ClickHouseClient, error) {
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)},
		Auth: clickhouse.Auth{
			Database: cfg.Database,
			Username: cfg.User,
			Password: cfg.Password,
		},
		Settings: clickhouse.Settings{
			"max_execution_time": 60,
		},
		Compression: &clickhouse.Compression{
			Method: clickhouse.CompressionLZ4,
		},
		MaxOpenConns:    10,
		MaxIdleConns:    5,
		ConnMaxLifetime: time.Hour,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to ClickHouse: %w", err)
	}

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := conn.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping ClickHouse: %w", err)
	}

	log.Info().
		Str("host", cfg.Host).
		Int("port", cfg.Port).
		Str("database", cfg.Database).
		Msg("Connected to ClickHouse")

	return &ClickHouseClient{conn: conn, cfg: cfg}, nil
}

// Close closes the ClickHouse connection
func (c *ClickHouseClient) Close() error {
	return c.conn.Close()
}

// Ping checks if the connection is alive
func (c *ClickHouseClient) Ping(ctx context.Context) error {
	return c.conn.Ping(ctx)
}

// GenerateFileID generates a deterministic file ID from the file path
func GenerateFileID(filePath string) string {
	hash := sha256.Sum256([]byte(filePath))
	return hex.EncodeToString(hash[:])
}

// ========== File Registry Operations ==========

// GetFileMetadata retrieves file metadata by file ID
func (c *ClickHouseClient) GetFileMetadata(ctx context.Context, fileID string) (*models.FileMetadata, error) {
	query := `
		SELECT file_id, file_path, file_size, last_modified, scan_status, 
		       ioc_count, minio_key, error_message, processed_at, updated_at
		FROM threat_intel.file_registry
		WHERE file_id = ?
		ORDER BY updated_at DESC
		LIMIT 1
	`

	row := c.conn.QueryRow(ctx, query, fileID)

	var meta models.FileMetadata
	var scanStatus string

	err := row.Scan(
		&meta.FileID,
		&meta.FilePath,
		&meta.FileSize,
		&meta.LastModified,
		&scanStatus,
		&meta.IOCCount,
		&meta.MinIOKey,
		&meta.ErrorMessage,
		&meta.ProcessedAt,
		&meta.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	meta.ScanStatus = models.ScanStatus(scanStatus)
	return &meta, nil
}

// CheckFileChanged checks if a file has changed since last scan
func (c *ClickHouseClient) CheckFileChanged(ctx context.Context, fileID string, lastModified time.Time) (bool, error) {
	query := `
		SELECT last_modified
		FROM threat_intel.file_registry
		WHERE file_id = ?
		ORDER BY updated_at DESC
		LIMIT 1
	`

	row := c.conn.QueryRow(ctx, query, fileID)

	var dbLastModified time.Time
	err := row.Scan(&dbLastModified)
	if err != nil {
		// File not found, treat as changed (new file)
		return true, nil
	}

	// File has changed if modification times differ
	return !dbLastModified.Equal(lastModified), nil
}

// UpsertFileMetadata inserts or updates file metadata
func (c *ClickHouseClient) UpsertFileMetadata(ctx context.Context, meta *models.FileMetadata) error {
	query := `
		INSERT INTO threat_intel.file_registry 
		(file_id, file_path, file_size, last_modified, scan_status, ioc_count, minio_key, error_message, processed_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	return c.conn.Exec(ctx, query,
		meta.FileID,
		meta.FilePath,
		meta.FileSize,
		meta.LastModified,
		string(meta.ScanStatus),
		meta.IOCCount,
		meta.MinIOKey,
		meta.ErrorMessage,
		meta.ProcessedAt,
		time.Now(),
	)
}

// ========== IOC Store Operations ==========

// BatchInsertIOCs inserts a batch of IOCs
func (c *ClickHouseClient) BatchInsertIOCs(ctx context.Context, iocs []models.IOC) error {
	if len(iocs) == 0 {
		return nil
	}

	batch, err := c.conn.PrepareBatch(ctx, `
		INSERT INTO threat_intel.ioc_store 
		(ioc_value, ioc_type, source_file_id, malware_family, confidence, first_seen, last_seen, hit_count, vector_id, tags)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare batch: %w", err)
	}

	for _, ioc := range iocs {
		err := batch.Append(
			ioc.Value,
			string(ioc.Type),
			ioc.SourceFileID,
			ioc.MalwareFamily,
			ioc.Confidence,
			ioc.FirstSeen,
			ioc.LastSeen,
			ioc.HitCount,
			ioc.VectorID,
			ioc.Tags,
		)
		if err != nil {
			return fmt.Errorf("failed to append to batch: %w", err)
		}
	}

	if err := batch.Send(); err != nil {
		return fmt.Errorf("failed to send batch: %w", err)
	}

	log.Debug().Int("count", len(iocs)).Msg("Batch inserted IOCs")
	return nil
}

// QueryIOCs queries IOCs by their values
func (c *ClickHouseClient) QueryIOCs(ctx context.Context, iocValues []string) ([]models.IOC, error) {
	if len(iocValues) == 0 {
		return nil, nil
	}

	query := `
		SELECT ioc_value, ioc_type, source_file_id, malware_family, confidence, 
		       first_seen, last_seen, hit_count, vector_id, tags
		FROM threat_intel.ioc_store
		WHERE ioc_value IN (?)
		ORDER BY last_seen DESC
	`

	rows, err := c.conn.Query(ctx, query, iocValues)
	if err != nil {
		return nil, fmt.Errorf("failed to query IOCs: %w", err)
	}
	defer rows.Close()

	var results []models.IOC
	for rows.Next() {
		var ioc models.IOC
		var iocType string

		err := rows.Scan(
			&ioc.Value,
			&iocType,
			&ioc.SourceFileID,
			&ioc.MalwareFamily,
			&ioc.Confidence,
			&ioc.FirstSeen,
			&ioc.LastSeen,
			&ioc.HitCount,
			&ioc.VectorID,
			&ioc.Tags,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		ioc.Type = models.IOCType(iocType)
		results = append(results, ioc)
	}

	return results, nil
}

// GetIOCStats returns statistics about IOCs by type
func (c *ClickHouseClient) GetIOCStats(ctx context.Context) (map[models.IOCType]int64, error) {
	query := `
		SELECT ioc_type, count() as cnt
		FROM threat_intel.ioc_store
		GROUP BY ioc_type
	`

	rows, err := c.conn.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query IOC stats: %w", err)
	}
	defer rows.Close()

	stats := make(map[models.IOCType]int64)
	for rows.Next() {
		var iocType string
		var count int64
		if err := rows.Scan(&iocType, &count); err != nil {
			return nil, err
		}
		stats[models.IOCType(iocType)] = count
	}

	return stats, nil
}

// GetFileStats returns statistics about processed files
func (c *ClickHouseClient) GetFileStats(ctx context.Context) (map[models.ScanStatus]int64, error) {
	query := `
		SELECT scan_status, count() as cnt
		FROM threat_intel.file_registry
		GROUP BY scan_status
	`

	rows, err := c.conn.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query file stats: %w", err)
	}
	defer rows.Close()

	stats := make(map[models.ScanStatus]int64)
	for rows.Next() {
		var status string
		var count int64
		if err := rows.Scan(&status, &count); err != nil {
			return nil, err
		}
		stats[models.ScanStatus(status)] = count
	}

	return stats, nil
}
