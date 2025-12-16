package db

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"

	"tip-server/internal/config"
)

// RedisClient wraps the Redis connection with Bloom Filter support
type RedisClient struct {
	client          *redis.Client
	cfg             config.RedisConfig
	bloomFilterName string
}

// NewRedisClient creates a new Redis client
func NewRedisClient(cfg config.RedisConfig) (*RedisClient, error) {
	client := redis.NewClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Password:     cfg.Password,
		DB:           cfg.DB,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		PoolSize:     100,
		MinIdleConns: 10,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	log.Info().
		Str("host", cfg.Host).
		Int("port", cfg.Port).
		Msg("Connected to Redis")

	rc := &RedisClient{
		client:          client,
		cfg:             cfg,
		bloomFilterName: cfg.BloomFilterName,
	}

	// Initialize Bloom Filter if it doesn't exist
	if err := rc.initBloomFilter(ctx); err != nil {
		log.Warn().Err(err).Msg("Failed to initialize Bloom Filter (may already exist)")
	}

	return rc, nil
}

// Close closes the Redis connection
func (r *RedisClient) Close() error {
	return r.client.Close()
}

// Ping checks if the connection is alive
func (r *RedisClient) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

// Client returns the underlying Redis client for custom operations
func (r *RedisClient) Client() *redis.Client {
	return r.client
}

// ========== Bloom Filter Operations ==========

// initBloomFilter creates the Bloom Filter if it doesn't exist
func (r *RedisClient) initBloomFilter(ctx context.Context) error {
	// Try to reserve a new Bloom Filter
	// This will fail if the filter already exists, which is fine
	err := r.client.BFReserve(ctx, r.bloomFilterName, r.cfg.BloomFilterErrorRate, r.cfg.BloomFilterCapacity).Err()
	if err != nil {
		// Check if it's because filter already exists
		info, infoErr := r.client.BFInfo(ctx, r.bloomFilterName).Result()
		if infoErr == nil {
			log.Info().
				Int64("capacity", info.Capacity).
				Int64("size", info.Size).
				Int64("items", info.ItemsInserted).
				Msg("Bloom Filter already exists")
			return nil
		}
		return err
	}

	log.Info().
		Str("name", r.bloomFilterName).
		Float64("error_rate", r.cfg.BloomFilterErrorRate).
		Int64("capacity", r.cfg.BloomFilterCapacity).
		Msg("Created new Bloom Filter")

	return nil
}

// BFAdd adds a single item to the Bloom Filter
func (r *RedisClient) BFAdd(ctx context.Context, item string) error {
	return r.client.BFAdd(ctx, r.bloomFilterName, item).Err()
}

// BFMAdd adds multiple items to the Bloom Filter
func (r *RedisClient) BFMAdd(ctx context.Context, items []string) error {
	if len(items) == 0 {
		return nil
	}

	// Convert []string to []interface{} for BFMAdd
	args := make([]interface{}, len(items))
	for i, item := range items {
		args[i] = item
	}

	return r.client.BFMAdd(ctx, r.bloomFilterName, args...).Err()
}

// BFExists checks if a single item exists in the Bloom Filter
func (r *RedisClient) BFExists(ctx context.Context, item string) (bool, error) {
	return r.client.BFExists(ctx, r.bloomFilterName, item).Result()
}

// BFMExists checks if multiple items exist in the Bloom Filter
// Returns a slice of booleans corresponding to each input item
func (r *RedisClient) BFMExists(ctx context.Context, items []string) ([]bool, error) {
	if len(items) == 0 {
		return nil, nil
	}

	// Convert []string to []interface{} for BFMExists
	args := make([]interface{}, len(items))
	for i, item := range items {
		args[i] = item
	}

	return r.client.BFMExists(ctx, r.bloomFilterName, args...).Result()
}

// BFInfo returns information about the Bloom Filter
func (r *RedisClient) BFInfo(ctx context.Context) (redis.BFInfo, error) {
	return r.client.BFInfo(ctx, r.bloomFilterName).Result()
}

// ========== Cache Operations ==========

// Set sets a key-value pair with expiration
func (r *RedisClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	return r.client.Set(ctx, key, value, expiration).Err()
}

// Get gets a value by key
func (r *RedisClient) Get(ctx context.Context, key string) (string, error) {
	return r.client.Get(ctx, key).Result()
}

// Delete deletes a key
func (r *RedisClient) Delete(ctx context.Context, keys ...string) error {
	return r.client.Del(ctx, keys...).Err()
}

// ========== Rate Limiting ==========

// RateLimitKey generates a rate limit key for an API key
func RateLimitKey(apiKeyHash string) string {
	return fmt.Sprintf("rate_limit:%s", apiKeyHash)
}

// IncrementRateLimit increments and checks rate limit
// Returns the current count and whether the limit was exceeded
func (r *RedisClient) IncrementRateLimit(ctx context.Context, apiKeyHash string, limit int, window time.Duration) (int64, bool, error) {
	key := RateLimitKey(apiKeyHash)

	// Use a Lua script for atomic increment + TTL check
	script := redis.NewScript(`
		local current = redis.call("INCR", KEYS[1])
		if current == 1 then
			redis.call("EXPIRE", KEYS[1], ARGV[1])
		end
		return current
	`)

	result, err := script.Run(ctx, r.client, []string{key}, int(window.Seconds())).Int64()
	if err != nil {
		return 0, false, err
	}

	return result, result > int64(limit), nil
}

// GetRateLimitRemaining returns remaining requests for an API key
func (r *RedisClient) GetRateLimitRemaining(ctx context.Context, apiKeyHash string, limit int) (int, error) {
	key := RateLimitKey(apiKeyHash)
	current, err := r.client.Get(ctx, key).Int()
	if err == redis.Nil {
		return limit, nil
	}
	if err != nil {
		return 0, err
	}

	remaining := limit - current
	if remaining < 0 {
		remaining = 0
	}
	return remaining, nil
}
