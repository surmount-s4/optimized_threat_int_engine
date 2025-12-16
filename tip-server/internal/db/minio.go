package db

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/rs/zerolog/log"

	"tip-server/internal/config"
)

// MinIOClient wraps the MinIO connection
type MinIOClient struct {
	client *minio.Client
	cfg    config.MinIOConfig
}

// NewMinIOClient creates a new MinIO client
func NewMinIOClient(cfg config.MinIOConfig) (*MinIOClient, error) {
	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create MinIO client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Check if bucket exists, create if not
	exists, err := client.BucketExists(ctx, cfg.Bucket)
	if err != nil {
		return nil, fmt.Errorf("failed to check bucket: %w", err)
	}

	if !exists {
		err = client.MakeBucket(ctx, cfg.Bucket, minio.MakeBucketOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to create bucket: %w", err)
		}
		log.Info().Str("bucket", cfg.Bucket).Msg("Created MinIO bucket")
	}

	log.Info().
		Str("endpoint", cfg.Endpoint).
		Str("bucket", cfg.Bucket).
		Msg("Connected to MinIO")

	return &MinIOClient{client: client, cfg: cfg}, nil
}

// Client returns the underlying MinIO client
func (m *MinIOClient) Client() *minio.Client {
	return m.client
}

// Bucket returns the configured bucket name
func (m *MinIOClient) Bucket() string {
	return m.cfg.Bucket
}

// ========== Object Operations ==========

// UploadFile uploads a file to MinIO
func (m *MinIOClient) UploadFile(ctx context.Context, objectName string, filePath string, contentType string) (*minio.UploadInfo, error) {
	info, err := m.client.FPutObject(ctx, m.cfg.Bucket, objectName, filePath, minio.PutObjectOptions{
		ContentType: contentType,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to upload file: %w", err)
	}

	log.Debug().
		Str("object", objectName).
		Int64("size", info.Size).
		Msg("Uploaded file to MinIO")

	return &info, nil
}

// UploadBytes uploads byte content to MinIO
func (m *MinIOClient) UploadBytes(ctx context.Context, objectName string, content []byte, contentType string) (*minio.UploadInfo, error) {
	reader := bytes.NewReader(content)

	info, err := m.client.PutObject(ctx, m.cfg.Bucket, objectName, reader, int64(len(content)), minio.PutObjectOptions{
		ContentType: contentType,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to upload bytes: %w", err)
	}

	log.Debug().
		Str("object", objectName).
		Int64("size", info.Size).
		Msg("Uploaded bytes to MinIO")

	return &info, nil
}

// UploadReader uploads from an io.Reader to MinIO
func (m *MinIOClient) UploadReader(ctx context.Context, objectName string, reader io.Reader, size int64, contentType string) (*minio.UploadInfo, error) {
	info, err := m.client.PutObject(ctx, m.cfg.Bucket, objectName, reader, size, minio.PutObjectOptions{
		ContentType: contentType,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to upload from reader: %w", err)
	}

	return &info, nil
}

// DownloadFile downloads a file from MinIO to local path
func (m *MinIOClient) DownloadFile(ctx context.Context, objectName string, filePath string) error {
	err := m.client.FGetObject(ctx, m.cfg.Bucket, objectName, filePath, minio.GetObjectOptions{})
	if err != nil {
		return fmt.Errorf("failed to download file: %w", err)
	}

	log.Debug().
		Str("object", objectName).
		Str("path", filePath).
		Msg("Downloaded file from MinIO")

	return nil
}

// GetObject retrieves an object as an io.ReadCloser
func (m *MinIOClient) GetObject(ctx context.Context, objectName string) (*minio.Object, error) {
	obj, err := m.client.GetObject(ctx, m.cfg.Bucket, objectName, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get object: %w", err)
	}

	return obj, nil
}

// GetObjectInfo retrieves object metadata without downloading content
func (m *MinIOClient) GetObjectInfo(ctx context.Context, objectName string) (minio.ObjectInfo, error) {
	info, err := m.client.StatObject(ctx, m.cfg.Bucket, objectName, minio.StatObjectOptions{})
	if err != nil {
		return minio.ObjectInfo{}, fmt.Errorf("failed to get object info: %w", err)
	}

	return info, nil
}

// DeleteObject deletes an object from MinIO
func (m *MinIOClient) DeleteObject(ctx context.Context, objectName string) error {
	err := m.client.RemoveObject(ctx, m.cfg.Bucket, objectName, minio.RemoveObjectOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete object: %w", err)
	}

	log.Debug().
		Str("object", objectName).
		Msg("Deleted object from MinIO")

	return nil
}

// ObjectExists checks if an object exists
func (m *MinIOClient) ObjectExists(ctx context.Context, objectName string) (bool, error) {
	_, err := m.client.StatObject(ctx, m.cfg.Bucket, objectName, minio.StatObjectOptions{})
	if err != nil {
		errResp := minio.ToErrorResponse(err)
		if errResp.Code == "NoSuchKey" {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// ListObjects lists objects with a prefix
func (m *MinIOClient) ListObjects(ctx context.Context, prefix string) <-chan minio.ObjectInfo {
	return m.client.ListObjects(ctx, m.cfg.Bucket, minio.ListObjectsOptions{
		Prefix:    prefix,
		Recursive: true,
	})
}

// ========== Utility Functions ==========

// GetContentType determines content type based on file extension
func GetContentType(filePath string) string {
	// Simple content type detection based on extension
	contentTypes := map[string]string{
		".txt":  "text/plain",
		".log":  "text/plain",
		".json": "application/json",
		".xml":  "application/xml",
		".html": "text/html",
		".csv":  "text/csv",
		".md":   "text/markdown",
		".yaml": "application/x-yaml",
		".yml":  "application/x-yaml",
		".conf": "text/plain",
		".cfg":  "text/plain",
		".ini":  "text/plain",
	}

	for ext, ct := range contentTypes {
		if len(filePath) > len(ext) && filePath[len(filePath)-len(ext):] == ext {
			return ct
		}
	}

	return "application/octet-stream"
}
