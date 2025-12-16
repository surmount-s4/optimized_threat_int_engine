-- Threat Intelligence Platform - Database Schema
-- This file is auto-executed by ClickHouse on container startup

CREATE DATABASE IF NOT EXISTS threat_intel;

-- 1. File Registry: Tracks the source of data and processing status
CREATE TABLE IF NOT EXISTS threat_intel.file_registry (
    file_id String,                -- SHA256(file_path) - deterministic ID
    file_path String,              -- Original file path
    file_size UInt64,              -- File size in bytes
    last_modified DateTime,        -- File modification time (for change detection)
    scan_status Enum8(
        'pending' = 0,
        'clean' = 1,
        'infected' = 2,
        'misc' = 3,
        'failed' = 4
    ),
    ioc_count UInt32 DEFAULT 0,    -- Number of IOCs found
    minio_key String DEFAULT '',   -- Link to MinIO if moved (for misc files)
    error_message String DEFAULT '',-- Error details if failed
    processed_at DateTime DEFAULT now(),
    updated_at DateTime DEFAULT now()
) ENGINE = ReplacingMergeTree(updated_at)
ORDER BY file_id;

-- 2. IOC Store: The main search index for Indicators of Compromise
CREATE TABLE IF NOT EXISTS threat_intel.ioc_store (
    ioc_value String,              -- The actual IOC (IP, hash, domain, etc.)
    ioc_type Enum8(
        'ipv4' = 1,
        'ipv6' = 2,
        'domain' = 3,
        'url' = 4,
        'md5' = 5,
        'sha1' = 6,
        'sha256' = 7,
        'email' = 8
    ),
    source_file_id String,         -- Link to file_registry
    malware_family String DEFAULT 'Unknown',
    confidence UInt8 DEFAULT 50,   -- Confidence score 0-100
    first_seen DateTime DEFAULT now(),
    last_seen DateTime DEFAULT now(),
    hit_count UInt32 DEFAULT 0,    -- Number of times queried
    vector_id Nullable(UInt64),    -- Reserved for Phase 2 Qdrant integration
    tags Array(String) DEFAULT [], -- Custom tags
    
    -- Bloom filter index for fast existence checks within ClickHouse
    INDEX idx_ioc_bloom ioc_value TYPE bloom_filter GRANULARITY 3,
    INDEX idx_type ioc_type TYPE set(8) GRANULARITY 1
) ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (ioc_type, ioc_value, source_file_id);

-- 3. API Keys: Authentication for API access
CREATE TABLE IF NOT EXISTS threat_intel.api_keys (
    key_hash String,               -- SHA256 of the API key
    key_name String,               -- Friendly name
    permissions Array(String),     -- ['read', 'write', 'admin']
    rate_limit UInt32 DEFAULT 1000,-- Requests per minute
    is_active UInt8 DEFAULT 1,
    created_at DateTime DEFAULT now(),
    last_used DateTime DEFAULT now()
) ENGINE = ReplacingMergeTree(last_used)
ORDER BY key_hash;

-- 4. Query Log: Audit trail of API queries
CREATE TABLE IF NOT EXISTS threat_intel.query_log (
    query_id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime DEFAULT now(),
    api_key_hash String,
    endpoint String,
    iocs_queried Array(String),
    iocs_found Array(String),
    response_time_ms UInt32,
    client_ip String DEFAULT ''
) ENGINE = MergeTree()
ORDER BY (timestamp, query_id)
TTL timestamp + INTERVAL 30 DAY;  -- Auto-delete after 30 days

-- Create materialized view for IOC statistics
CREATE MATERIALIZED VIEW IF NOT EXISTS threat_intel.ioc_stats
ENGINE = SummingMergeTree()
ORDER BY (ioc_type, date)
AS SELECT
    ioc_type,
    toDate(first_seen) AS date,
    count() AS count
FROM threat_intel.ioc_store
GROUP BY ioc_type, date;
